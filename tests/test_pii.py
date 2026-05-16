from mcpshield.detectors.pii import scan_pii, redact


def test_email_detected():
    detections = scan_pii("contact me at pranav@hpe.com please")
    assert any(d.rule == "email" for d in detections)


def test_sg_phone_detected():
    detections = scan_pii("call me at +65 9123 4567")
    assert any(d.rule == "phone_sg" for d in detections)


def test_nric_detected():
    detections = scan_pii("my NRIC is S1234567D")
    assert any(d.rule == "nric_sg" for d in detections)


def test_credit_card_detected():
    detections = scan_pii("card: 4111 1111 1111 1111")
    assert any(d.rule == "credit_card" for d in detections)


def test_redact_email():
    redacted, detections = redact("email me at foo@bar.com")
    assert "foo@bar.com" not in redacted
    assert "[REDACTED-EMAIL]" in redacted


def test_clean_text_no_pii():
    detections = scan_pii("the weather in Singapore is hot today")
    assert len(detections) == 0