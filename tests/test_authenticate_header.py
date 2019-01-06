from authparser import AuthParser


def handler():
    pass


def test_single_scheme_single_line_implicit():
    # arrange
    parser = AuthParser()
    parser.add_handler('Basic', handler)

    # act
    authenticate = parser.get_challenge_header()

    # assert
    assert len(authenticate) == 1
    assert 'WWW-Authenticate' in authenticate
    assert authenticate['WWW-Authenticate'] == 'Basic'


def test_single_scheme_single_line_explicit():
    # arrange
    parser = AuthParser()
    parser.add_handler('Basic', handler)

    # act
    authenticate = parser.get_challenge_header(multi_line=False)

    # assert
    assert len(authenticate) == 1
    assert 'WWW-Authenticate' in authenticate
    assert authenticate['WWW-Authenticate'] == 'Basic'


def test_single_scheme_multi_line():
    # arrange
    parser = AuthParser()
    parser.add_handler('Basic', handler)

    # act
    authenticate = parser.get_challenge_header(multi_line=True)

    # assert
    assert len(authenticate) == 1
    assert len(authenticate[0]) == 1
    assert 'WWW-Authenticate' in authenticate[0]
    assert authenticate[0]['WWW-Authenticate'] == 'Basic'


def test_multiple_schemes():
    # arrange
    parser = AuthParser()
    parser.add_handler('Basic', handler)
    parser.add_handler('Bearer', handler)

    # act
    authenticate = parser.get_challenge_header(multi_line=True)

    # assert
    assert len(authenticate) == 2


def test_multiple_schemes_single_line():
    # arrange
    parser = AuthParser()
    parser.add_handler('Basic', handler)
    parser.add_handler('Bearer', handler)

    # act
    authenticate = parser.get_challenge_header()

    # assert
    assert len(authenticate) == 1
    assert 'WWW-Authenticate' in authenticate
    assert authenticate['WWW-Authenticate'] == 'Basic, Bearer'


def test_single_scheme_default_params():
    # arrange
    parser = AuthParser()
    parser.add_handler('Basic', handler, realm="pointw.com")

    # act
    authenticate = parser.get_challenge_header()

    # assert
    assert len(authenticate) == 1
    assert 'WWW-Authenticate' in authenticate
    assert authenticate['WWW-Authenticate'] == 'Basic realm="pointw.com"'


def test_single_scheme_runtime_params():
    # arrange
    def basic_challenge(**kwargs):
        realm = kwargs.get('realm')
        if realm:
            return {'realm': realm}

    parser = AuthParser()
    parser.add_handler('Basic', handler, basic_challenge)

    # act
    authenticate = parser.get_challenge_header(realm="pointw.com")

    # assert
    assert len(authenticate) == 1
    assert 'WWW-Authenticate' in authenticate
    assert authenticate['WWW-Authenticate'] == 'Basic realm="pointw.com"'


def test_multiple_schemes_runtime_params_single_line():
    # arrange
    def basic_challenge(**kwargs):
        realm = kwargs.get('realm')
        if realm:
            return {'realm': realm}

    def bearer_challenge(**kwargs):
        error = kwargs.get('error')
        if error:
            return {'error': 'invalid_token'}

    parser = AuthParser()
    parser.add_handler('Basic', handler, basic_challenge)
    parser.add_handler('Bearer', handler, bearer_challenge)

    # act
    authenticate = parser.get_challenge_header(realm="pointw.com", error=True)

    # assert
    assert len(authenticate) == 1
    assert 'WWW-Authenticate' in authenticate
    assert authenticate['WWW-Authenticate'] == 'Basic realm="pointw.com", Bearer error="invalid_token"'


def test_multiple_schemes_runtime_params_multi_line():
    # arrange
    def basic_challenge(**kwargs):
        realm = kwargs.get('realm')
        if realm:
            return {'realm': realm}

    def bearer_challenge(**kwargs):
        error = kwargs.get('error')
        if error:
            return {'error': 'invalid_token'}

    parser = AuthParser()
    parser.add_handler('Basic', handler, basic_challenge)
    parser.add_handler('Bearer', handler, bearer_challenge)

    # act
    authenticate = parser.get_challenge_header(realm="pointw.com", error=True, multi_line=True)

    # assert
    assert len(authenticate) == 2
    assert len(authenticate[0]) == 1
    assert 'WWW-Authenticate' in authenticate[0]
    assert len(authenticate[1]) == 1
    assert 'WWW-Authenticate' in authenticate[1]
    assert authenticate[0]['WWW-Authenticate'] == 'Basic realm="pointw.com"'
    assert authenticate[1]['WWW-Authenticate'] == 'Bearer error="invalid_token"'
