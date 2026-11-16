"""Tests for the UIS second-factor (TOTP) login path.

Covers the behaviour that made the daily run fail after the school started
answering the password step with a pending second factor:
  * TOTP codes match RFC 6238;
  * a pending challenge is reported as SecondFactorError, not a vague
    "no loginToken";
  * the challenge is completed through the offered userAndOtp module;
  * a configuration the runner cannot satisfy fails once, without hammering
    UIS, and never reports a fake success;
  * the WebVPN portal pre-flight classifies redirects instead of treating
    every 302 as a dead session.
"""

import unittest
from unittest.mock import Mock, patch

from src.api import webvpn
from src.api.webvpn import SecondFactorError, WebVPNSession
from src.api.webvpn import _icourse_login_token, _redirect_category, totp_code


# RFC 6238 reference secret, ASCII "12345678901234567890" in Base32.
RFC_KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


class FakeSession:
    """Records requests and replays queued responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.closed = False

    def post(self, url, **kwargs):
        self.calls.append(("post", url, kwargs))
        return self.responses.pop(0)

    def get(self, url, **kwargs):
        self.calls.append(("get", url, kwargs))
        return self.responses.pop(0)

    def close(self):
        self.closed = True


def make_session(responses):
    vpn = WebVPNSession()
    vpn.session = FakeSession(responses)
    return vpn


CHALLENGE = {
    "code": 200,
    "data": None,
    "second": True,
    "moduleCodes": ["userAndOtp"],
    "requestNumber": "req-1",
    "authChainCode": "otp-chain",
    "userName": "tester",
    "message": "second factor required",
}


class TotpCodeTests(unittest.TestCase):
    def test_matches_rfc6238_vectors(self):
        # RFC 6238 SHA1 vectors, truncated to the six digits UIS asks for.
        self.assertEqual(totp_code(RFC_KEY, 59), "287082")
        self.assertEqual(totp_code(RFC_KEY, 1111111109), "081804")
        self.assertEqual(totp_code(RFC_KEY, 2000000000), "279037")

    def test_secret_whitespace_and_padding_are_tolerated(self):
        spaced = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq=="
        self.assertEqual(totp_code(spaced, 59), "287082")

    def test_missing_secret_is_a_second_factor_error(self):
        with self.assertRaisesRegex(SecondFactorError, "UIS_TOTP_SECRET is not configured"):
            totp_code("")

    def test_invalid_secret_is_a_second_factor_error(self):
        with self.assertRaisesRegex(SecondFactorError, "not a valid Base32"):
            totp_code("not-base32-!!!")


class ChallengeDetectionTests(unittest.TestCase):
    def test_challenge_is_reported_instead_of_a_missing_token(self):
        with self.assertRaises(SecondFactorError) as ctx:
            _icourse_login_token(dict(CHALLENGE))
        message = str(ctx.exception)
        self.assertIn("second factor", message)
        self.assertIn("userAndOtp", message)
        # The summary must not leak response values such as the request number.
        self.assertNotIn("req-1", message)

    def test_token_is_still_read_from_top_level_and_data(self):
        self.assertEqual(_icourse_login_token({"code": 200, "loginToken": "top"}), "top")
        self.assertEqual(
            _icourse_login_token({"code": 200, "data": {"loginToken": "nested"}}),
            "nested",
        )

    def test_plain_error_is_not_mistaken_for_a_challenge(self):
        with self.assertRaises(RuntimeError) as ctx:
            _icourse_login_token({"code": 500, "message": "boom"})
        self.assertNotIsInstance(ctx.exception, SecondFactorError)


class TotpChallengeTests(unittest.TestCase):
    def test_challenge_is_completed_with_the_offered_otp_module(self):
        vpn = make_session([FakeResponse({"code": 200, "loginToken": "after-otp"})])
        with patch.object(webvpn.config, "TOTP_SECRET", RFC_KEY), \
                patch.object(webvpn, "time") as fake_time:
            fake_time.time.return_value = 59
            result = vpn._authenticate_totp(
                dict(CHALLENGE), "tester", "lck-1", "entity", "pwd-chain",
                "chain_type",
            )
        self.assertEqual(result["loginToken"], "after-otp")
        method, url, kwargs = vpn.session.calls[0]
        self.assertEqual(method, "post")
        self.assertTrue(url.endswith("/idp/authn/authExecute"))
        self.assertEqual(kwargs["json"]["authModuleCode"], "userAndOtp")
        self.assertEqual(kwargs["json"]["requestNumber"], "req-1")
        self.assertEqual(kwargs["json"]["authChainCode"], "otp-chain")
        self.assertEqual(kwargs["json"]["requestType"], "chain_type")
        self.assertEqual(kwargs["json"]["authPara"]["loginName"], "tester")
        self.assertEqual(kwargs["json"]["authPara"]["otpCode"], "287082")

    def test_challenge_without_the_otp_module_stops_with_a_clear_message(self):
        vpn = make_session([])
        challenge = dict(CHALLENGE, moduleCodes=["userAndSms"])
        with self.assertRaisesRegex(SecondFactorError, "userAndSms"):
            vpn._authenticate_totp(
                challenge, "tester", "lck", "entity", "chain", "chain_type"
            )
        self.assertEqual(vpn.session.calls, [])

    def test_missing_secret_fails_before_any_request(self):
        vpn = make_session([])
        with patch.object(webvpn.config, "TOTP_SECRET", ""):
            with self.assertRaises(SecondFactorError):
                vpn._authenticate_totp(
                    dict(CHALLENGE), "tester", "lck", "entity", "chain",
                    "chain_type",
                )
        self.assertEqual(vpn.session.calls, [])

    def test_rejected_code_is_a_second_factor_error(self):
        vpn = make_session([FakeResponse({"code": 401, "message": "bad otp"})])
        with patch.object(webvpn.config, "TOTP_SECRET", RFC_KEY):
            with self.assertRaisesRegex(SecondFactorError, "rejected"):
                vpn._authenticate_totp(
                    dict(CHALLENGE), "tester", "lck", "entity", "chain",
                    "chain_type",
                )

    def test_a_further_step_is_never_reported_as_success(self):
        follow_up = dict(CHALLENGE, requestNumber="req-2")
        vpn = make_session([FakeResponse(follow_up)])
        with patch.object(webvpn.config, "TOTP_SECRET", RFC_KEY):
            with self.assertRaisesRegex(SecondFactorError, "further step"):
                vpn._authenticate_totp(
                    dict(CHALLENGE), "tester", "lck", "entity", "chain",
                    "chain_type",
                )

    def test_network_failure_is_a_second_factor_error(self):
        vpn = make_session([])
        vpn.session.post = Mock(side_effect=webvpn.requests.ConnectionError("down"))
        with patch.object(webvpn.config, "TOTP_SECRET", RFC_KEY):
            with self.assertRaisesRegex(SecondFactorError, "ConnectionError"):
                vpn._authenticate_totp(
                    dict(CHALLENGE), "tester", "lck", "entity", "chain",
                    "chain_type",
                )


class RedirectClassificationTests(unittest.TestCase):
    def test_login_redirect_is_cold(self):
        self.assertEqual(
            _redirect_category("https://webvpn.fudan.edu.cn/login?cas_login=true"),
            "login",
        )

    def test_same_host_non_login_redirect_is_the_portal(self):
        self.assertEqual(
            _redirect_category("/por/index?a=1#frag"), "portal"
        )

    def test_other_host_is_external(self):
        self.assertEqual(
            _redirect_category("https://id.fudan.edu.cn/ac/?lck=1"), "external"
        )

    def test_missing_location_is_not_a_portal(self):
        self.assertEqual(_redirect_category(""), "none")


class LoginRetryTests(unittest.TestCase):
    def test_second_factor_failure_is_not_retried(self):
        try:
            import main
        except ImportError as exc:  # optional heavy deps (sherpa-onnx, ...)
            self.skipTest(f"main import unavailable: {exc}")
        with patch.object(main, "WebVPNSession") as factory:
            factory.return_value.login.side_effect = SecondFactorError("needs TOTP")
            with self.assertRaisesRegex(SecondFactorError, "retries stopped"):
                main.login_with_retry(max_attempts=10)
        self.assertEqual(factory.return_value.login.call_count, 1)


if __name__ == "__main__":
    unittest.main()
