#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
import webbrowser

import requests
from electrum.bitcoin import (TYPE_ADDRESS, is_address)
from electrum.i18n import _

from electrum import Transaction
from electrum import simple_config
import copy, traceback
from lib.cryptagio import (MODE_JH_FUND, MODE_JH_FLUSH)
from .util import *
from decimal import Decimal
from electrum.util import NotEnoughFunds

class WithdrawalsList(MyTreeWidget):
    filter_columns = [0, 1, 2, 3]  # Address, Amount, Max_Fee, Tx_Id

    def __init__(self, parent=None, currency_code='OMNI'):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 1)
        self.headers = [_('Address'), _('Amount'), _('MaxFee'), _('TxId')]
        self.setColumnCount(len(self.headers))
        self.setHeaderLabels(self.headers)
        self.header().setStretchLastSection(False)
        for col in range(len(self.headers)):
            sm = QHeaderView.Stretch if col == self.stretch_column else QHeaderView.ResizeToContents
            self.header().setSectionResizeMode(col, sm)

        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.jh_is_loading = False
        self.fund_button = EnterButton(_("Fund"), self.do_fund)
        self.fund_button.setToolTip(_('Fund income OMNI addresses'))
        self.transfer_button = EnterButton(_("Transfer"), self.do_transfer)
        self.transfer_button.setToolTip(_('Transfer from income OMNI addresses'))

        self.refresh_button = EnterButton(_("Withdrawals"), self.do_refresh)
        self.refresh_button.setToolTip(_('Refresh Withdrawal requests from Cryptagio'))
        self.withdrawals = []
        self.currency = currency_code

    def get_list_header(self):
        return QLabel(_("OMNI:")), self.fund_button, self.transfer_button, self.refresh_button

    def do_fund(self):

        SEGWIT_TX = False
        POS_TYPE = 0
        POS_ADDRESS = 1  # address position in an output tuple

        if not self.wallet.omni:
            self.parent.show_error(_('Funding intended for OMNI wallets only'))
            return

        if self.jh_is_loading:
            self.parent.show_error(_('Synchronization in process. Please wait'))
            return

        currency = self.wallet.omni_code
        jh_host = self.config.get('jh_host', '').rstrip('/')
        jh_key = self.config.get('jh_key', '')
        if jh_host == '' or jh_key == '':
            self.parent.show_error(_('Check your Jackhammer preferences'))
            return

        def update_addresses():
            addresses = []
            headers = {
                'x-api-key': jh_key
            }

            lastId = 0
            while True:
                api_route = jh_host + "/export/address/" + currency + "?last_id=" + str(lastId)
                r = requests.get(api_route, headers=headers)
                if r.status_code is not requests.codes.ok:
                    self.parent.show_error(
                        _('Error response from Jackhammer. Code: ') + ("%s" % r.status_code) + r.text)
                    return None

                response = r.json()
                if response is None or not len(response):
                    return addresses

                for addr in response:
                    path = addr.get('hd_key', '')
                    if path == '':
                        self.parent.show_error(_('Bad response from Jackhammer'))
                        return None
                    address = addr.get('address', '')
                    lastId = addr.get('id', 0)

                    if self.wallet.is_mine(address):
                        addresses.append((address, lastId))
                        self.wallet.add_addr_id(address, lastId)
                        continue

                    if self.wallet.is_ignored_address(address):
                        continue

                    hd_address = self.wallet.create_hd_address(path)
                    if hd_address == address:
                        self.wallet.save_hd_address(address, path)
                        self.wallet.add_receiving_address(address)
                        addresses.append((address, lastId))
                        self.wallet.add_addr_id(address, lastId)
                    else:
                        self.wallet.add_ignored_address(address)

        self.jh_is_loading = True
        try:
            tx_id, tx_hash, tx_hex = self.parent.cryptagio.tx_get(currency, MODE_JH_FUND)
        except Exception as e:
            return self.parent.show_error(_('Exception in update_addresses:\n' + str(e)))
        finally:
            self.jh_is_loading = False

        if tx_hex is not None:
            tx = Transaction(tx_hex)
            tx.deserialize()
            fund_list = None
        else:
            self.jh_is_loading = True
            try:
                fund_addresses = update_addresses()
            except Exception as e:
                return self.parent.show_error(_('Exception in update_addresses:\n' + str(e)))
            finally:
                self.jh_is_loading = False

            dust = self.wallet.dust_threshold()
            origin_address = self.wallet.omni_address
            '''
            fund_addresses = copy.deepcopy(self.wallet.get_receiving_addresses())
            try:
                fund_addresses.remove(origin_address)
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                pass

            if fund_addresses is None or len(fund_addresses) == 0:
                self.parent.show_message(_('No income addresses'))
                return
            '''

            # hardcoded fund in BTC
            max_fee = self.parent.cryptagio.get_max_fee('BTC')
            fee_estimator = self.parent.get_send_fee_estimator()
            if fee_estimator is None:
                fee_estimator = partial(
                    simple_config.SimpleConfig.estimate_fee_for_feerate, self.wallet.relayfee())

            # self.wallet.wait_until_synchronized()

            outputs = []
            fund_list = []
            for addr, id in fund_addresses:
                if addr is None:
                    return self.parent.show_error(_('Fund Address is None'))
                if not is_address(addr):
                    return self.parent.show_error(_('Invalid Fund Address'))

                omni_balance = self.wallet.omni_addr_balance([addr])
                if omni_balance <= 0:
                    continue

                c, u, x = self.wallet.get_addr_balance(addr)
                btc_balance = c + u + x

                utxos = self.wallet.get_addr_utxo(addr)
                coins = []
                for x in utxos.values():
                    self.wallet.add_input_info(x)
                    coins.append(x)

                tx_hex = self.parent.get_omni_tx(self.wallet.omni_address, omni_balance, max_fee, coins)
                if tx_hex is None:
                    continue

                tx = Transaction(tx_hex)
                tx.deserialize()

                base_tx = Transaction.from_io([], tx.outputs()[:])
                base_weight = base_tx.estimated_weight()

                # hardcoded segwit = False
                weight_in = 0
                for inp in coins:
                    weight_in += Transaction.estimated_input_weight(inp, SEGWIT_TX)

                size = Transaction.virtual_size_from_weight(base_weight + weight_in)
                fee = fee_estimator(size)

                # TODO: Add change ???

                if btc_balance < (dust + fee):
                    # add input
                    amount = dust + fee - btc_balance
                    if amount < dust:
                        amount = dust

                    inp = {'address': addr, 'value': amount, 'prevout_n': 0, 'prevout_hash': '00' * 32, 'height': 1,
                           'coinbase': False, 'type': 'address'}
                    self.wallet.add_input_info(inp)
                    delta_weight = Transaction.estimated_input_weight(inp, SEGWIT_TX)
                    delta_fee = fee_estimator(Transaction.virtual_size_from_weight(delta_weight))
                    amount = dust + fee + delta_fee - btc_balance
                    inp['value'] = amount
                    coins.append(inp)
                    btc_balance += amount

                    outputs.append((TYPE_ADDRESS, addr, int(amount)))
                    fund_list.append(id)

            if len(outputs) <= 0:
                self.parent.show_message(_("Funding do not required"))
                return

            fee = None

            # get available coins (for origin address only)
            utxos = self.wallet.get_addr_utxo(origin_address)
            coins = []
            for x in utxos.values():
                self.wallet.add_input_info(x)
                coins.append(x)

            max_fee_satoshi = int(self.parent.cryptagio.max_fee_amount * pow(10, 8))
            while (not fee) or (fee > max_fee_satoshi):

                if fee and fee > max_fee_satoshi:
                    fee_estimator = max_fee_satoshi
                try:
                    tx = self.wallet.make_unsigned_transaction(
                        coins, outputs, self.config, fixed_fee=fee_estimator)
                except NotEnoughFunds:
                    self.parent.show_message(_("Insufficient funds"))
                    return
                except BaseException as e:
                    traceback.print_exc(file=sys.stdout)
                    self.parent.show_message(str(e))
                    return

                fee = tx.get_fee()

            use_rbf = self.parent.config.get('use_rbf', True)
            if use_rbf:
                tx.set_rbf(True)

            if fee < self.wallet.relayfee() * tx.estimated_size() / 1000:
                self.parent.show_error(
                    _("This transaction requires a higher fee, or it will not be propagated by the network"))
                return

            tx_id = None
            tx_hash = None

        # tx is restored from db or builded
        self.parent.show_transaction(tx, 'Funding OMNI income addresses',
                                     tx_id, tx_hash, currency, jh_mode=MODE_JH_FUND, ids=fund_list)

    def do_transfer(self):

        if not self.wallet.omni:
            self.parent.show_error(_('Flushing intended for OMNI wallets only'))
            return

        if self.jh_is_loading:
            self.parent.show_error(_('Synchronization in process. Please wait'))
            return

        currency = self.wallet.omni_code

        self.jh_is_loading = True
        try:
            tx_id, tx_hash, tx_hex = self.parent.cryptagio.tx_get(currency, MODE_JH_FLUSH)
        except Exception as e:
            return self.parent.show_error(_('Exception in update_addresses:\n' + str(e)))
        finally:
            self.jh_is_loading = False

        if tx_hex is not None:
            tx = Transaction(tx_hex)
            tx.deserialize()

            # TODO: get flush_id from outputs[]
            inps = tx.inputs()
            if len(inps) <= 0:
                return self.parent.show_error(_('Wrong OMNI tx received from JH: ' + str(len(inps)) + ' inputs'))
            addr = inps[0].get('address', '')
            id = self.wallet.get_addr_id(addr)
            if id is None:
                self.parent.show_error(_("OMNI fund required"))
                return

        else:
            origin_address = self.wallet.omni_address
            fund_addresses = copy.deepcopy(self.wallet.get_receiving_addresses())
            try:
                fund_addresses.remove(origin_address)
            except Exception as e:
                traceback.print_exc(file=sys.stdout)
                pass

            if fund_addresses is None or len(fund_addresses) == 0:
                self.parent.show_message(_('No income addresses'))
                return

            # build balances dictionary
            balances = {}
            for addr in fund_addresses:
                if addr is None:
                    return self.parent.show_error(_('Fund Address is None'))
                if not is_address(addr):
                    return self.parent.show_error(_('Invalid Fund Address'))

                omni_balance = self.wallet.omni_addr_balance([addr])
                if omni_balance > 0:
                    balances[addr] = omni_balance

            if len(balances) == 0:
                self.parent.show_message(_('Income OMNI not found'))
                return

            # sorted_balances = sorted(balances.items(), key=operator.itemgetter(1), reverse=True)

            addr = max(balances, key=balances.get)
            omni_balance = balances[addr]
            id = self.wallet.get_addr_id(addr)
            if id is None:
                self.parent.show_error(_("OMNI fund required"))
                return

            # hardcoded fund in BTC
            max_fee = self.parent.cryptagio.get_max_fee('BTC')
            fee_estimator = self.parent.get_send_fee_estimator()
            if fee_estimator is None:
                fee_estimator = partial(
                    simple_config.SimpleConfig.estimate_fee_for_feerate, self.wallet.relayfee())

            # for addr, omni_balance in sorted_balances:
            # c, u, x = self.wallet.get_addr_balance(addr)
            # btc_balance = c + u + x

            utxos = self.wallet.get_addr_utxo(addr)
            coins = []
            for x in utxos.values():
                self.wallet.add_input_info(x)
                coins.append(x)

            tx_hex = self.parent.get_omni_tx(self.wallet.omni_address, omni_balance, max_fee, coins)
            if tx_hex is None:
                self.parent.show_error(_("Error in building OMNI flush transaction"))
                return

            tx = Transaction(tx_hex)
            tx.deserialize()

            fee = None

            max_fee_satoshi = int(self.parent.cryptagio.max_fee_amount * pow(10, 8))
            while (not fee) or (fee > max_fee_satoshi):

                if fee and fee > max_fee_satoshi:
                    fee_estimator = max_fee_satoshi
                try:
                    tx = self.wallet.make_unsigned_transaction(
                        coins, tx.outputs(), self.config, fixed_fee=fee_estimator)
                except NotEnoughFunds:
                    self.parent.show_error(_("Insufficient funds"))
                    return
                except BaseException as e:
                    traceback.print_exc(file=sys.stdout)
                    self.parent.show_message(str(e))
                    return

                fee = tx.get_fee()

            # amount = tx.output_value() if self.is_max else sum(map(lambda x: x[2], outputs))

            use_rbf = self.parent.config.get('use_rbf', True)
            if use_rbf:
                tx.set_rbf(True)

            if fee < self.wallet.relayfee() * tx.estimated_size() / 1000:
                self.parent.show_error(_("This transaction requires a higher fee, "
                                         "or it will not be propagated by the network"))
                return

            tx_id, tx_hash = None, None

        self.parent.show_transaction(tx, 'Transfer OMNI from income address',
                                     tx_id, tx_hash, currency, jh_mode=MODE_JH_FLUSH, ids=[id])

    def do_refresh(self):
        if not self.parent.wallet.omni:
            self.parent.show_error(_('Withdrawals intended for OMNI wallets only'))
            return

        if self.jh_is_loading:
            self.parent.show_error(_('Synchronization in process. Please wait'))
            return

        self.jh_is_loading = True
        # self.update()

        tx_hash, fee, tx_body = self.parent.cryptagio.check_for_uncorfimed_tx(self.currency)

        if not tx_hash is None or not fee is None or not tx_body is None:
            from electrum.transaction import SerializationError
            try:
                tx = self.parent.tx_from_text(tx_body)
                if tx:
                    self.parent.show_transaction(tx, '', self.parent.cryptagio.tx_id, self.parent.cryptagio.tx_body_hash)
            except SerializationError as e:
                self.show_critical(_("Electrum was unable to deserialize the transaction:") + "\n" + str(e))

            self.jh_is_loading = False
            return

        def amount_format(amount):
            # DECIMAL_PRECISION = 8
            REQUIRED_LEN = 9  # 1 + 8
            s = str(amount)
            if len(s) < REQUIRED_LEN:
                s = (REQUIRED_LEN - len(s))*'0' + s
            fs = s[:-8] + '.' + s[-8:]
            return fs

        def get_withdrawals(currency_code):
            INVALID_VALUE = -1
            withdrawals = []
            cryptagio_host = self.config.get('cryptagio_host', '').rstrip('/')
            cryptagio_key = self.config.get('cryptagio_key', '')

            headers = {
                'x-api-key': cryptagio_key
            }

            api_route = cryptagio_host + "/wallet/" + currency_code + "/omnirequest"
            if cryptagio_host == '' or cryptagio_key == '':
                self.parent.show_error(_('Check your Cryptagio preferences'))
                return []

            r = requests.get(api_route, headers=headers)
            if r.status_code is not requests.codes.ok:
                self.parent.show_error(_('Bad response from Cryptagio. Code: ') + ("%s" % r.status_code) + r.text)
                return []

            response = r.json()
            if response is None or not len(response):
                self.parent.show_message(_('No new withdrawal requests yet'))
                return []

            if not len(response.get('requests', [])):
                self.parent.show_message(_('No new withdrawal requests yet'))
                return []

            for item in response.get('requests', []):
                address = item.get('address', '')
                # amount = Decimal(item.get('amount', '')) * Decimal(1e-8)
                amount = amount_format(item.get('amount', 0))
                if address == '' or amount == '':
                    self.parent.show_error(_('Bad response from Cryptagio. Address or amount is empty'))
                    return []

                tx_id = item.get('tx_id', INVALID_VALUE)
                max_fee_amount = item.get('max_fee_amount', INVALID_VALUE)   # in BTC (!!!)
                if tx_id == INVALID_VALUE or max_fee_amount == INVALID_VALUE:
                    self.parent.show_error(_('No tx_id or max_fee_amount in Cryptagio response'))
                    return []

                withdrawals.append((address, amount, Decimal(max_fee_amount), tx_id))

            return withdrawals

        try:
            self.withdrawals = get_withdrawals(self.currency)
        except Exception as e:
            print(e)
            self.parent.show_error(_('Exception during withdrawal request ' + '\n' + str(e)))

        self.jh_is_loading = False
        self.update()

    def on_update(self):
        self.wallet = self.parent.wallet
        item = self.currentItem()
        current_addr = item.data(0, Qt.UserRole) if item else None
        #addr_list = self.wallet.get_change_addresses() if self.show_change else self.wallet.get_receiving_addresses()
        self.clear()

        if self.jh_is_loading:
            address_item = QTreeWidgetItem(["Loading withdrawal requests from Cryptagio", "", "", ""])
            self.addChild(address_item)
            return

        if self.withdrawals is None:
            address_item = QTreeWidgetItem(["No new withdrawal requests from Cryptagio", "", "", ""])
            self.addChild(address_item)
            return

        for item in self.withdrawals:
            addr = item[0]
            amount = str(item[1])
            max_fee = str(item[2])
            tx_id = str(item[3])

            wr_item = QTreeWidgetItem([addr, amount, max_fee, tx_id])
            #wr_item.setTextAlignment(3, Qt.AlignRight)
            #wr_item.setFont(0, QFont(MONOSPACE_FONT))
            wr_item.setData(0, Qt.UserRole, addr)
            #wr_item.setData(0, Qt.UserRole + 1, True)  # label can be edited
            self.addChild(wr_item)
            if addr == current_addr:
                self.setCurrentItem(wr_item)

    def create_menu(self, position):
        selected = self.selectedItems()
        multi_select = len(selected) > 1
        #addrs = [item.text(0) for item in selected]
        #if not addrs:
        #    return

        menu = QMenu()
        if not multi_select:
            item = self.itemAt(position)
            #col = self.currentColumn()
            if not item:
                return
            #column_title = self.headerItem().text(col)
            #copy_text = item.text(col)
            #withdrawal = self.withdrawals[position]
            addr = item.text(0)
            if not is_address(addr):
                item.setExpanded(not item.isExpanded())
                return
            amount = item.text(1)
            max_fee = item.text(2)
            tx_id = item.text(3)
            menu.addAction(_("Build Transaction"), lambda: self.parent.build_tx(addr, amount, max_fee, tx_id))

        #coins = self.wallet.get_utxos(addrs)
        #if coins:
        #    menu.addAction(_("Spend from"), lambda: self.parent.spend_coins(coins))

        #run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # labels for headings, e.g. "receiving" or "used" should not be editable
        return item.childCount() == 0
