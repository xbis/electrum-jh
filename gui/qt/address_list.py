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
from electrum.i18n import _
from electrum.plugins import run_hook
from electrum.util import (block_explorer_URL, NotEnoughFunds)
from .util import *
from electrum.bitcoin import (TYPE_ADDRESS, TYPE_SCRIPT, is_address)

#from electrum.wallet import (relayfee, Imported_Wallet)
#from electrum.storage import WalletStorage
from electrum import Transaction
from electrum import simple_config
import copy, traceback, operator


class AddressList(MyTreeWidget):
    filter_columns = [0, 1, 2]  # Address, Label, Balance

    def __init__(self, parent=None):
        MyTreeWidget.__init__(self, parent, self.create_menu, [], 1)
        self.refresh_headers()
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.show_change = False
        self.show_used = 0
        self.jh_is_loading = False
        self.change_button = QComboBox(self)
        self.change_button.currentIndexChanged.connect(self.toggle_change)
        for t in [_('Receiving'), _('Change')]:
            self.change_button.addItem(t)
        self.used_button = QComboBox(self)
        self.used_button.currentIndexChanged.connect(self.toggle_used)
        for t in [_('All'), _('Unused'), _('Funded'), _('Used')]:
            self.used_button.addItem(t)
        self.refresh_button = EnterButton(_("JH Refresh"), self.do_refresh)
        self.refresh_button.setToolTip(_('Refresh HD wallet balances'))
        self.fund_button = EnterButton(_("OMNI Fund"), self.do_fund)
        self.fund_button.setToolTip(_('Fund income OMNI addresses'))
        self.transfer_button = EnterButton(_("OMNI Transfer"), self.do_transfer)
        self.transfer_button.setToolTip(_('Transfer from income OMNI addresses'))

        #def on_omni_change(x):
        #    self.omni = x == Qt.Checked

        #self.omni_cb = QCheckBox(_('OMNI'))
        #self.omni_cb.setChecked(self.parent.omni_cryptagio)
        #self.omni_cb.stateChanged.connect(on_omni_change)
        #self.omni_cb.setToolTip(
        #    _('Check to filter OMNI addresses'))


    def get_list_header(self):
        #self.omni_cb.setChecked(self.parent.omni_cryptagio)
        return QLabel(_("Filter:")), self.change_button, self.used_button, self.refresh_button, self.fund_button, self.transfer_button

    def do_refresh(self):
        if self.jh_is_loading:
            self.parent.show_error(_('Synchronization in process. Please wait'))
            return

        self.jh_is_loading = True

        def a():
            currency = self.wallet.omni_code if self.wallet.omni else 'BTC'
            jh_host = self.config.get('jh_host', '').rstrip('/')
            jh_key = self.config.get('jh_key', '')

            headers = {
                'x-api-key': jh_key
            }

            lastId = 0
            while True:
                api_route = jh_host + "/export/address/" + currency + "?last_id=" + str(lastId)
                if jh_host == '' or jh_key == '':
                    return self.parent.show_error(_('Check your Jackhammer preferences'))

                r = requests.get(api_route, headers=headers)
                if r.status_code is not requests.codes.ok:
                    return self.parent.show_error(_('Bad response from Jackhammer. Code: ') + ("%s" % r.status_code) + r.text)

                response = r.json()
                if response is None or not len(response):
                    return

                for addr in response:
                    path = addr.get('hd_key', '')
                    if path == '':
                        return self.parent.show_error(_('Bad response from Jackhammer'))

                    address = addr.get('address', '')
                    lastId = addr.get('id', 0)

                    hd_address = self.wallet.create_hd_address(path)
                    if address == hd_address:
                        self.wallet.save_hd_address(address, path)

                # addresses not imported => exit
                if lastId == 0:
                    break

        try:
            a()
        except Exception as e:
            print(e)
            self.parent.show_error(_('Exception during request '))

        self.jh_is_loading = False
        self.update()


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

        self.jh_is_loading = True

        def update_addresses():
            currency = self.wallet.omni_code if self.wallet.omni else 'BTC'
            jh_host = self.config.get('jh_host', '').rstrip('/')
            jh_key = self.config.get('jh_key', '')

            headers = {
                'x-api-key': jh_key
            }

            lastId = 0
            while True:
                api_route = jh_host + "/export/address/" + currency + "?last_id=" + str(lastId)
                if jh_host == '' or jh_key == '':
                    self.parent.show_error(_('Check your Jackhammer preferences'))
                    return

                r = requests.get(api_route, headers=headers)
                if r.status_code is not requests.codes.ok:
                    self.parent.show_error(_('Bad response from Jackhammer. Code: ') + ("%s" % r.status_code) + r.text)
                    return

                response = r.json()
                if response is None or not len(response):
                    return

                for addr in response:
                    path = addr.get('hd_key', '')
                    if path == '':
                        self.parent.show_error(_('Bad response from Jackhammer'))
                        return
                    address = addr.get('address', '')
                    lastId = addr.get('id', 0)

                    if self.wallet.is_mine(address):
                        continue

                    if self.wallet.is_ignored_address(address):
                        continue

                    hd_address = self.wallet.create_hd_address(path)
                    if hd_address == address:
                        self.wallet.save_hd_address(address, path)
                        self.wallet.add_receiving_address(address)
                    else:
                        self.wallet.add_ignored_address(address)

        dust = self.wallet.dust_threshold()

        try:
            update_addresses()
        except Exception as e:
            return self.parent.show_error(_('Exception in update_addresses:\n' + str(e)))
        finally:
            self.jh_is_loading = False

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

        # hardcoded fund in BTC
        max_fee = self.parent.cryptagio.get_max_fee('BTC')
        fee_estimator = self.parent.get_send_fee_estimator()
        if fee_estimator is None:
            fee_estimator = partial(
                simple_config.SimpleConfig.estimate_fee_for_feerate, self.wallet.relayfee())

        self.wallet.wait_until_synchronized()

        outputs = []
        for addr in fund_addresses:
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

            while True:
                #hardcoded witness = False
                weight_in = 0
                for inp in coins:
                    weight_in += Transaction.estimated_input_weight(inp, SEGWIT_TX)

                size = Transaction.virtual_size_from_weight(base_weight + weight_in)
                fee = fee_estimator(size)

                # TODO: Add change ???

                if btc_balance >= (dust + fee):
                    # nothing to fund
                    break

                # add input
                amount = dust + fee - btc_balance
                if amount < dust:
                    amount = dust

                inp = {'address': addr, 'value': amount, 'prevout_n': 0, 'prevout_hash': '00'*32, 'height': 1, 'coinbase': False, 'type': 'address'}
                self.wallet.add_input_info(inp)
                delta_weight = Transaction.estimated_input_weight(inp, SEGWIT_TX)
                delta_fee = fee_estimator(Transaction.virtual_size_from_weight(delta_weight))
                amount = dust + fee + delta_fee - btc_balance
                inp['value'] = amount
                coins.append(inp)
                btc_balance += amount

                outputs.append((TYPE_ADDRESS, addr, int(amount)))

        if len(outputs) <= 0:
            self.show_message(_("Funding do not required"))
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
                self.show_message(_("Insufficient funds"))
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

        if fee < self.wallet.relayfee() * tx.estimated_size() / 1000 :
            self.parent.show_error(_("This transaction requires a higher fee, or it will not be propagated by the network"))
            return

        self.parent.show_transaction(tx, 'Funding OMNI income addresses', None, None) #tx_hash

    def do_transfer(self):

        if not self.wallet.omni:
            self.parent.show_error(_('Funding intended for OMNI wallets only'))
            return

        if self.jh_is_loading:
            self.parent.show_error(_('Synchronization in process. Please wait'))
            return

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

        sorted_balances = sorted(balances.items(), key=operator.itemgetter(1), reverse=True)

        #max_addr = max(balances.iteritems(), key=operator.itemgetter(1))[0]
        #max_amount = balances[max_addr]

        # hardcoded fund in BTC
        max_fee = self.parent.cryptagio.get_max_fee('BTC')
        fee_estimator = self.parent.get_send_fee_estimator()
        if fee_estimator is None:
            fee_estimator = partial(
                simple_config.SimpleConfig.estimate_fee_for_feerate, self.wallet.relayfee())

        for addr, omni_balance in sorted_balances:

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

            if fee < self.wallet.relayfee() * tx.estimated_size() / 1000 :
                self.parent.show_error(_("This transaction requires a higher fee, or it will not be propagated by the network"))
                return

            # debug
            break

        self.parent.show_transaction(tx, 'Transfer OMNI from income address', None, None) #tx_hash

    def refresh_headers(self):
        headers = [_('Address'), _('Label'), _('Balance')]
        fx = self.parent.fx
        if fx and fx.get_fiat_address_config():
            headers.extend([_(fx.get_currency() + ' Balance')])
        headers.extend([_('Tx')])
        self.update_headers(headers)

    def toggle_change(self, show):
        show = bool(show)
        if show == self.show_change:
            return
        self.show_change = show
        self.update()

    def toggle_used(self, state):
        if state == self.show_used:
            return
        self.show_used = state
        self.update()

    def on_update(self):
        self.wallet = self.parent.wallet
        item = self.currentItem()
        current_address = item.data(0, Qt.UserRole) if item else None
        addr_list = self.wallet.get_change_addresses() if self.show_change else self.wallet.get_receiving_addresses()
        self.clear()

        if self.jh_is_loading:
            address_item = QTreeWidgetItem(["Loading addresses from Jackhammer", "", "", ""])
            self.addChild(address_item)
            return

        for address in addr_list:
            num = len(self.wallet.history.get(address, []))
            is_used = self.wallet.is_used(address)
            label = self.wallet.labels.get(address, '')
            c, u, x = self.wallet.get_addr_balance(address)
            balance = c + u + x
            if self.show_used == 1 and (balance or is_used):
                continue
            if self.show_used == 2 and balance == 0:
                continue
            if self.show_used == 3 and not is_used:
                continue
            balance_text = self.parent.format_amount(balance)
            fx = self.parent.fx
            if fx and fx.get_fiat_address_config():
                rate = fx.exchange_rate()
                fiat_balance = fx.value_str(balance, rate)
                address_item = QTreeWidgetItem([address, label, balance_text, fiat_balance, "%d" % num])
                address_item.setTextAlignment(3, Qt.AlignRight)
            else:
                address_item = QTreeWidgetItem([address, label, balance_text, "%d" % num])
                address_item.setTextAlignment(2, Qt.AlignRight)
            address_item.setFont(0, QFont(MONOSPACE_FONT))
            address_item.setData(0, Qt.UserRole, address)
            address_item.setData(0, Qt.UserRole + 1, True)  # label can be edited
            if self.wallet.is_frozen(address):
                address_item.setBackground(0, ColorScheme.BLUE.as_color(True))
            if self.wallet.is_beyond_limit(address, self.show_change):
                address_item.setBackground(0, ColorScheme.RED.as_color(True))
            self.addChild(address_item)
            if address == current_address:
                self.setCurrentItem(address_item)

    def create_menu(self, position):
        from electrum.wallet import Multisig_Wallet
        is_multisig = isinstance(self.wallet, Multisig_Wallet)
        can_delete = self.wallet.can_delete_address()
        selected = self.selectedItems()
        multi_select = len(selected) > 1
        addrs = [item.text(0) for item in selected]
        if not addrs:
            return
        if not multi_select:
            item = self.itemAt(position)
            col = self.currentColumn()
            if not item:
                return
            addr = addrs[0]
            if not is_address(addr):
                item.setExpanded(not item.isExpanded())
                return

        menu = QMenu()
        if not multi_select:
            column_title = self.headerItem().text(col)
            copy_text = item.text(col)
            menu.addAction(_("Copy %s") % column_title, lambda: self.parent.app.clipboard().setText(copy_text))
            menu.addAction(_('Details'), lambda: self.parent.show_address(addr))
            if col in self.editable_columns:
                menu.addAction(_("Edit %s") % column_title, lambda: self.editItem(item, col))
            menu.addAction(_("Request payment"), lambda: self.parent.receive_at(addr))
            if self.wallet.can_export():
                menu.addAction(_("Private key"), lambda: self.parent.show_private_key(addr))
            if not is_multisig and not self.wallet.is_watching_only():
                menu.addAction(_("Sign/verify message"), lambda: self.parent.sign_verify_message(addr))
                menu.addAction(_("Encrypt/decrypt message"), lambda: self.parent.encrypt_message(addr))
            if can_delete:
                menu.addAction(_("Remove from wallet"), lambda: self.parent.remove_address(addr))
            addr_URL = block_explorer_URL(self.config, 'addr', addr)
            if addr_URL:
                menu.addAction(_("View on block explorer"), lambda: webbrowser.open(addr_URL))

            if not self.wallet.is_frozen(addr):
                menu.addAction(_("Freeze"), lambda: self.parent.set_frozen_state([addr], True))
            else:
                menu.addAction(_("Unfreeze"), lambda: self.parent.set_frozen_state([addr], False))

        coins = self.wallet.get_utxos(addrs)
        if coins:
            menu.addAction(_("Spend from"), lambda: self.parent.spend_coins(coins))

        run_hook('receive_menu', menu, addrs, self.wallet)
        menu.exec_(self.viewport().mapToGlobal(position))

    def on_permit_edit(self, item, column):
        # labels for headings, e.g. "receiving" or "used" should not be editable
        return item.childCount() == 0
