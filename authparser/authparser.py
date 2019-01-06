"""
Parses an http Authorization: header into a structure (token or params)
and passes to a handler for the auth scheme.
"""
import pyparsing as pp
from collections import OrderedDict


class AuthParser:
    """
    Use pyparsing to create a parser for Authentication headers.  This parser will be used
    to select which scheme handler to call.
    """
    def __init__(self):
        ##########
        # the following is a translation into pyparsing objects of the ABNF described here:
        # https://tools.ietf.org/html/rfc7235#page-17
        tchar_non_alphanums = "!#$%&'*+-.^_`|~"
        tchar = tchar_non_alphanums + pp.nums + pp.alphas
        t68char = '-._~+/' + pp.nums + pp.alphas

        token = pp.Word(tchar)
        token68 = pp.Combine(pp.Word(t68char) + pp.ZeroOrMore('='))

        scheme = token('scheme')

        auth_header = pp.Keyword('Authorization')
        name = pp.Word(pp.alphas, pp.alphanums)
        value = pp.quotedString.setParseAction(pp.removeQuotes)
        name_value_pair = name + pp.Suppress('=') + value
        params = pp.Dict(pp.delimitedList(pp.Group(name_value_pair)))

        credentials = scheme + (token68('token') ^ params('params'))
        ##########

        # scheme: used to by add_handler() to validate the scheme name
        # auth_parser: used by get_user_record() to parse the header
        # auth_schemes: this will hold the handler functions and additional params
        self.scheme = scheme
        self.auth_parser = auth_header + pp.Suppress(':') + credentials
        self.auth_schemes = OrderedDict()

    def add_handler(self, scheme, user_record_fn, challenge_fn=None, **kwargs):
        """
        Maps the handler functions and optionally default properties to the scheme name
        - i.e. adds this scheme and its details to the auth_schemes dict

        :param scheme: Which scheme these details are for, e.g. Basic, Bearer, Digest, etc.

        :param user_record_fn: the function this class will call when translating an Authorization header
               into a user record.
               - The function must accept one param which will either be
                 a token (string) or a params (dict of name-value pairs) (see RFC 7235).
               - The function may accept **kwargs, which this class merely passes through.  Use for whatever purposes
                 makes sense in your application/handler

        :param challenge_fn: [optional] - if provided, get_challenge_header() will call this to add parameters
               to this scheme's details in the WWW-Authenticate header.
               - If this function returns a dict of name-value pairs, those will be added to the header as params of
                 this scheme

        :param kwargs: passed through to get_challenge_header() which are used as default parameters to add to
               this scheme's params in the WWW-Authenticate header.

        :return: None
        """
        try:
            self.scheme.parseString(scheme)
        except pp.ParseException as ex:
            raise ValueError('{0} is not a validly named scheme ({1})'.format(scheme, ex))

        # TODO: use inspect.getargspec(func) and/or inspect.signature(func) to check the func's params
        if not hasattr(user_record_fn, '__call__'):
            raise ValueError('user_record_fn must be callable')

        if challenge_fn:
            if not hasattr(challenge_fn, '__call__'):
                raise ValueError('when specifying challenge_fn, it must be callable')

        self.auth_schemes[scheme] = {}
        self.auth_schemes[scheme]['params'] = kwargs
        self.auth_schemes[scheme]['user_record_fn'] = user_record_fn
        self.auth_schemes[scheme]['challenge_fn'] = challenge_fn

    def clear_handlers(self):
        """
        Clears all scheme handlers.

        :return: None
        """
        self.auth_schemes = OrderedDict()

    def get_user_record(self, auth_header, **kwargs):
        """
        Parse auth_header and call the scheme's handler to get the user record

        :param auth_header: The Authorization header string.

        :param kwargs: additional parameters to pass to the scheme handler

        :return: user_record - whatever the scheme handler returned, which could be
                 - a dict of claims or other details
                 - a boolean whether the header contains authentic credentials
        """
        if not auth_header.startswith('Authorization:'):
            auth_header = 'Authorization: ' + auth_header

        try:
            parsed = self.auth_parser.parseString(auth_header)
            scheme = parsed['scheme']

            try:
                user_record_fn = self.auth_schemes[scheme]['user_record_fn']
                auth_info = parsed['token'] if 'token' in parsed.keys() else parsed['params']
                user_record = user_record_fn(auth_info, **kwargs)
            except (KeyError, AttributeError):
                raise ValueError('No handler available for this authorization scheme: {0}'.format(scheme))

        except pp.ParseException:
            raise SyntaxError('Cannot parse the Authorization header')

        return user_record

    def get_challenge_header(self, **kwargs):
        """
        Returns a WWW-Authenticate header (or headers) based on which scheme handlers this instance has
        been configured to handle.

        :param kwargs: passed through to the handler to do with them as they wish.  This method will look
               in kwargs for 'single_line' (see :return for details)

        :return: an array of dict {'WWW-Authenticate': string-list-of-schemes-and-their-params}
        e.g. [{'WWW-Authenticate': 'Basic realm="pointw.com"},{'WWW-Authenticate': 'Bearer realm="pointw.com"}]
        - OR if this method is called with single_line=True, the above array is collapsed to a single dict
        e.g. {'WWW-Authenticate': 'Basic realm="pointw.com", Bearer realm="pointw.com"}
        """
        challenges = []
        for scheme in self.auth_schemes.keys():
            challenge = scheme

            params = self.auth_schemes[scheme].get('params', {})
            challenge_fn = self.auth_schemes[scheme]['challenge_fn']
            if challenge_fn:
                challenge_params = challenge_fn(**kwargs)
                if isinstance(challenge_params, dict):
                    params.update(challenge_params)

            if params:
                if not challenge == scheme:
                    challenge += ','
                challenge += self._flatten_params(params)

            challenges.append(challenge)

        if kwargs.get('multi_line'):
            rtn = []
            for challenge in challenges:
                rtn.append({'WWW-Authenticate': '{0}'.format(challenge)})
        else:
            rtn = {'WWW-Authenticate': ''}

            first = True
            for challenge in challenges:
                sep = ', '
                if first:
                    first = False
                    sep = ''
                rtn['WWW-Authenticate'] += sep + challenge

        return rtn

    @staticmethod
    def _flatten_params(params):
        rtn = ''

        first = True
        for param in params.keys():
            sep = ', '
            if first:
                first = False
                sep = ' '
            rtn += '{0}{1}="{2}"'.format(sep, param, params[param])

        return rtn
