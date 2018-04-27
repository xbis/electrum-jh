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
from electrum.bitcoin import is_address
from electrum.i18n import _
from electrum.plugins import run_hook
from electrum.util import block_explorer_URL

from .util import *
from decimal import Decimal

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
        self.refresh_button = EnterButton(_("Withdrawals Refresh"), self.do_refresh)
        self.refresh_button.setToolTip(_('Refresh Withdrawal requests from Cryptagio'))
        self.withdrawals = []
        self.currency = currency_code

    def get_list_header(self):
        return QLabel(_("Filter:")), self.refresh_button

    def do_refresh(self):
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
            withdrawals = []
            cryptagio_host = self.config.get('cryptagio_host', '').rstrip('/')
            cryptagio_key = self.config.get('cryptagio_key', '')

            headers = {
                'x-api-key': cryptagio_key
            }

            api_route = cryptagio_host + "/wallet/" + currency_code + "/omnirequest"
            if cryptagio_host == '' or cryptagio_key == '':
                return self.parent.show_error(_('Check your Cryptagio preferences'))

            r = requests.get(api_route, headers=headers)
            if r.status_code is not requests.codes.ok:
                return self.parent.show_error(_('Bad response from Cryptagio. Code: ') + ("%s" % r.status_code) + r.text)

            response = r.json()
            if response is None or not len(response):
                return

            if not len(response.get('requests', [])):
                return self.parent.show_message(_('No new withdrawal requests yet'))

            for item in response.get('requests', []):
                address = item.get('address', '')
                # amount = Decimal(item.get('amount', '')) * Decimal(1e-8)
                amount = amount_format(item.get('amount', 0))
                if address == '' or amount == '':
                    return self.parent.show_error(_('Bad response from Cryptagio. Address or amount is empty'))

                tx_id = item.get('tx_id', 0)
                max_fee_amount = Decimal(item.get('max_fee_amount', 0))   # in BTC (!!!)
                if not tx_id or not max_fee_amount:
                    return self.parent.show_error(_('No tx_id or max_fee_amount in Cryptagio response'))

                withdrawals.append((address, amount, max_fee_amount, tx_id))

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
