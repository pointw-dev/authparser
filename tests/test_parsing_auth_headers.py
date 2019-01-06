from authparser import AuthParser
import base64
import pytest

##########
# dummy handlers


def basic(token):
    try:
        u, p = base64.b64decode(token).decode().split(':', 1)
    except Exception:
        raise ValueError('Basic token is malformed')

    return {'username': u, 'password': p}


def from_token(token):
    return {'token': token}


def from_parameters(params):
    return params
##########


scenarios = ('scheme, header, details, handler', [
    pytest.param('Basic', 'Authorization: Basic Zm9vOmJhcg==', {
        'username': 'foo',
        'password': 'bar'
    }, basic, id='Basic'),

    pytest.param('Bearer', 'Authorization: Bearer cn389ncoiwuencr', {
        'token': 'cn389ncoiwuencr'
    }, from_token, id='Bearer'),

    pytest.param('Digest', 'Authorization: Digest qop="chap", realm="testrealm@example.com", username="Foobar", response="6629fae49393a05397450978507c4ef1", cnonce="5ccc069c403ebaf9f0171e9517f40e41"', {
        "qop": "chap",
        "realm": "testrealm@example.com",
        "username": "Foobar",
        "response": "6629fae49393a05397450978507c4ef1",
        "cnonce": "5ccc069c403ebaf9f0171e9517f40e41"
    }, from_parameters, id='Digest'),

    pytest.param('Basic', u'Authorization: Basic bWljaGFlbDp0ZXN0', {
        'username': 'michael',
        'password': 'test'
    }, basic, id='Basic [unicode]'),

    pytest.param('AWS4-HMAC-SHA256', 'Authorization: AWS4-HMAC-SHA256 Credential="AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request", SignedHeaders="host;range;x-amz-date", Signature="fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"', {
        "Credential": "AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request",
        "SignedHeaders": "host;range;x-amz-date",
        "Signature": "fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024"
    }, from_parameters, id="AWS4-HMAC-SHA256")
])


@pytest.mark.parametrize(*scenarios)
def test_valid_headers(scheme, header, details, handler):
    # arrange
    parser = AuthParser()
    parser.add_handler(scheme, handler)

    # act
    record = parser.get_user_record(header)

    # assert
    for key in details:
        assert key in record
        assert details[key] == record[key]


@pytest.mark.parametrize(*scenarios)
def test_partial_headers(scheme, header, details, handler):
    # arrange
    partial_header = header.split('Authorization: ')[1]
    parser = AuthParser()
    parser.add_handler(scheme, handler)

    # act
    record = parser.get_user_record(partial_header)

    # assert
    for key in details:
        assert key in record
        assert details[key] == record[key]


def test_clear_handlers():
    # arrange
    parser = AuthParser()
    parser.add_handler('Bearer', from_token)
    parser.clear_handlers()
    header = 'Authorization: Bearer cn389ncoiwuencr'

    # act
    with pytest.raises(ValueError) as ex:
        parser.get_user_record(header)

    # assert
    assert ex.value.args[0] == 'No handler available for this authorization scheme: Bearer'


def test_not_handled_scheme():
    # arrange
    parser = AuthParser()
    parser.add_handler('Basic', basic)
    header = 'Authorization: CrazyCustom foo="bar", fizz="buzz"'

    # act
    with pytest.raises(ValueError) as ex:
        parser.get_user_record(header)

    # assert
    assert ex.value.args[0] == 'No handler available for this authorization scheme: CrazyCustom'


def test_malformed_header():
    # arrange
    parser = AuthParser()
    parser.add_handler('Basic', basic)
    header = 'Authorization: bad-header'

    # act
    with pytest.raises(SyntaxError) as ex:
        parser.get_user_record(header)

    # assert
    assert ex.value.args[0] == 'Cannot parse the Authorization header'


def test_get_record_not_callable():
    # arrange
    parser = AuthParser()
    handler = 'handler'

    # act
    with pytest.raises(ValueError) as ex:
        parser.add_handler('Basic', handler)

    # assert
    assert ex.value.args[0] == 'user_record_fn must be callable'


def test_challenge_not_callable():
    # arrange
    parser = AuthParser()
    challenge = 'challenge'

    # act
    with pytest.raises(ValueError) as ex:
        parser.add_handler('Basic', basic, challenge)

    # assert
    assert ex.value.args[0] == 'when specifying challenge_fn, it must be callable'
