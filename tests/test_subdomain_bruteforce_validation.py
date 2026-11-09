from recon_engine.modules.subdomain_bruteforce import _valid_hostnames_only


def test_real_hostnames_pass_through():
    lines = ["shop.tesla.com", "dev-1.shop.tesla.com", "tesla.com"]
    assert _valid_hostnames_only(lines) == lines


def test_puredns_massdns_error_text_is_rejected():
    lines = [
        "unable to execute massdns. make sure it is present and that the",
        "path to the binary is added to the path environment variable.",
        "alternatively, specify the path to massdns using --bin",
    ]
    assert _valid_hostnames_only(lines) == []


def test_mixed_output_keeps_only_real_hostnames():
    lines = ["shop.tesla.com", "puredns error: something broke"]
    assert _valid_hostnames_only(lines) == ["shop.tesla.com"]


def test_blank_lines_ignored():
    assert _valid_hostnames_only(["", "  ", "shop.tesla.com"]) == ["shop.tesla.com"]
