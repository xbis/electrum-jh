import requests
from electrum.i18n import _
from decimal import Decimal

# 18/04/24
# param currency_code added

#CODE_BTC = 'BTC'
#CODE_OMNI = 'OMNI'


class Cryptagio(object):

    MAX_FEE_BTC = 0.0001
    CODE_BTC = 'BTC'

    def __init__(self, parent):
        self.parent = parent
        self.is_loading = False
        self.max_fee_amount = Decimal(self.MAX_FEE_BTC)  # TODO: use this some way

    def set_params(self):
        #self.currency_code = "BTC"
        self.cryptagio_host = self.parent.config.get('cryptagio_host', '')
        self.cryptagio_host = self.cryptagio_host.rstrip('/')
        self.cryptagio_key = self.parent.config.get('cryptagio_key', '')
        self.headers = {
            'x-api-key': self.cryptagio_key
        }

        self.tx_id = None
        self.tx_body_hash = None

    def check_for_uncorfimed_tx(self, currency_code):
        if self.is_loading:
            return self.parent.show_error(_('Data load is in process. Please wait'))

        self.is_loading = True

        def make_request():
            self.set_params()
            if self.cryptagio_host == '' or self.cryptagio_key == '':
                return self.parent.show_error(_('Check your Cryptagio preferences'))
            api_requests_route = self.cryptagio_host + "/wallet/" + currency_code + "/transaction"

            r = requests.get(api_requests_route, headers=self.headers, params={})

            if r.status_code is not requests.codes.ok:
                return self.parent.show_error(
                    _('Bad response from Cryptagio. Code: ') + ("%s" % r.status_code) + r.text)

            response = r.json()
            if not len(response):
                return None, None, None
            self.tx_id = response['Id']
            self.tx_body_hash = response['TxbodyHash']
            self.max_fee_amount = Decimal(response['MaxFee'])*1000 #in uBTC
            return response['TxHash'], response['Fee'], response['Txbody']

        tx_hash, fee, tx_body = None, None, None
        try:
            tx_hash, fee, tx_body = make_request()
        except Exception as err:
            print(err)
            self.parent.show_error(_('Exception during check_for_uncorfimed_tx request'))

        self.is_loading = False

        return tx_hash, fee, tx_body

    def get_outputs(self, currency_code):
        if self.is_loading:
            return self.parent.show_error(_('Data load is in process. Please wait'))

        self.is_loading = True

        def make_request():
            outputs = []
            self.set_params()
            if self.cryptagio_host == '' or self.cryptagio_key == '':
                return self.parent.show_error(_('Check your Cryptagio preferences'))

            api_requests_route = self.cryptagio_host + "/wallet/" + currency_code + "/request"

            r = requests.get(api_requests_route, headers=self.headers, params={})

            if r.status_code is not requests.codes.ok:
                return self.parent.show_error(
                    _('Bad response from Cryptagio. Code: ') + ("%s" % r.status_code) + r.text)

            response = r.json()

            if not len(response.get('requests', [])):
                return self.parent.show_message(_('No new withdrawal requests yet'))

            self.tx_id = response.get('tx_id', 0)
            if not self.tx_id:
                return self.parent.show_error(_('No tx_id in Cryptagio response'))

            self.max_fee_amount = Decimal(response.get('max_fee_amount', 0))*1000 #in uBTC
            if not self.max_fee_amount:
                return self.parent.show_error(_('No max_fee_amount in Cryptagio response'))

            for item in response.get('requests', []):
                address = item.get('address', '')
                amount = int(item.get('amount', ''))
                if address == '' or amount == '':
                    return self.parent.show_error(_('Bad response from Cryptagio. Address or amount is empty'))

                obj_type, address = self.parent.payto_e.parse_output(address)
                outputs.append((obj_type, address, amount))

            return outputs

        outputs = []
        try:
            outputs = make_request()
        except Exception as err:
            print(err)
            self.parent.show_error(_('Exception during get_outputs request'))

        self.is_loading = False
        return outputs

    def get_requests(self, currency_code):
        if self.is_loading:
            return self.parent.show_error(_('Data load is in process. Please wait'))

        self.is_loading = True

        def make_request():
            requests = []
            self.set_params()
            if self.cryptagio_host == '' or self.cryptagio_key == '':
                return self.parent.show_error(_('Check your Cryptagio preferences'))

            api_requests_route = self.cryptagio_host + "/wallet/" + currency_code + "/omnirequest"

            r = requests.get(api_requests_route, headers=self.headers, params={})

            if r.status_code is not requests.codes.ok:
                return self.parent.show_error(
                    _('Bad response from Cryptagio. Code: ') + ("%s" % r.status_code) + r.text)

            response = r.json()

            if not len(response.get('requests', [])):
                return self.parent.show_message(_('No new withdrawal requests yet'))

            for item in response.get('requests', []):
                address = item.get('address', '')
                amount = int(item.get('amount', ''))
                if address == '' or amount == '':
                    return self.parent.show_error(_('Bad response from Cryptagio. Address or amount is empty'))

                tx_id = item.get('tx_id', 0)
                max_fee_amount = Decimal(item.get('max_fee_amount', 0)) * 1000  # in uBTC
                if not tx_id or not self.max_fee_amount:
                    return self.parent.show_error(_('No tx_id or max_fee_amount in Cryptagio response'))

                requests.append((address, amount, max_fee_amount, tx_id))

            return requests

        requests = []
        try:
            requests = make_request()
        except Exception as err:
            print(err)
            self.parent.show_error(_('Exception during get_outputs request'))

        self.is_loading = False
        return requests

    def get_fund_addresses(self, currency_code):
        if self.is_loading:
            return self.parent.show_error(_('Data load is in process. Please wait'))

        self.is_loading = True

        def make_request():
            addresses = []
            self.set_params()
            if self.cryptagio_host == '' or self.cryptagio_key == '':
                return self.parent.show_error(_('Check your Cryptagio preferences'))

            api_requests_route = self.cryptagio_host + "/fund/addreses/" + currency_code

            r = requests.get(api_requests_route, headers=self.headers, params={})
            '''
            if r.status_code is not requests.codes.ok:
                return self.parent.show_error(
                    _('Bad response from Cryptagio. Code: ') + ("%s" % r.status_code) + r.text)

            response = r.json()
            '''
            response = ["2N8t3moL5wT4By5FBTcyyt5r3zx8MLvmVAr", "2NFy5cHB3VCZLE4JH6fGGUo8k2bHReLQoPY", "2N2wN2f1Gqpk3R4hRkn1kuFXPAg3gohY77B"]
            '''            
            if not len(response.get('requests', [])):
                return self.parent.show_message(_('No new addreses to fund'))
            '''
            #for item in response.get('requests', []):
            for item in response:
                addresses.append(item)

            return addresses

        outputs = []
        try:
            outputs = make_request()
        except Exception as err:
            print(err)
            self.parent.show_error(_('Exception during get_fund_addresses request'))

        self.is_loading = False
        return outputs

    def update_tx(self, tx_id, tx_hash, fee, tx_body, tx_prev_body_hash, currency_code):
        if self.is_loading:
            return self.parent.show_error(_('Data load is in process. Please wait'))

        self.is_loading = True

        def make_request():
            api_tx_route = self.cryptagio_host + "/wallet/" + currency_code + "/transaction/" + str(tx_id)
            r = requests.post(api_tx_route, headers=self.headers, data={
                'tx_hash': tx_hash,
                'tx_body': tx_body,
                'fee': fee,
                'tx_prev_body_hash': tx_prev_body_hash,
                # 'state': "Processing", # this one sets automatically
            })
            if r.status_code is not requests.codes.ok:
                return self.parent.show_error(
                    _('Bad response from Jackhammer. Code: ') + ("%s" % r.status_code) + r.text)
            response = r.json()

            return response['tx_body_hash']

        tx_body_hash = ""
        try:
            tx_body_hash = make_request()
        except Exception as err:
            self.parent.show_error(_('Exception during update_tx request'))

        self.is_loading = False

        return tx_body_hash

    def approve_tx(self, tx_id, tx_body, tx_prev_body_hash, currency_code):
        if self.is_loading:
            return self.parent.show_error(_('Data load is in process. Please wait'))

        self.is_loading = True

        def make_request():
            api_tx_route = self.cryptagio_host + "/wallet/" + currency_code + "/transaction/" + str(tx_id)
            r = requests.post(api_tx_route, headers=self.headers, data={
                'tx_body': tx_body,
                'tx_prev_body_hash': tx_prev_body_hash,
                'state': "Done",
            })
            if r.status_code is not requests.codes.ok:
                return self.parent.show_error(
                    _('Bad response from Jackhammer. Code: ') + ("%s" % r.status_code) + r.text)
            response = r.json()

            return response['tx_body_hash']

        tx_body_hash = ""
        try:
            tx_body_hash = make_request()
        except Exception as err:
            self.parent.show_error(_('Exception during update_tx request'))

        self.is_loading = False

        return tx_body_hash

    def get_max_fee(self, currency_code):

        max_fee = self.MAX_FEE_BTC

        if currency_code != self.CODE_BTC:
            return None

        return max_fee
