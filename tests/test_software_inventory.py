from scanner.software_inventory import build_software_inventory


def test_builds_inventory_from_open_port_service_data() -> None:
    scan_result = {
        "host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "open_ports": [
            {
                "host": "127.0.0.1",
                "resolved_ip": "127.0.0.1",
                "port": 22,
                "protocol": "tcp",
                "service": "ssh",
                "status": "open",
                "confidence": "high",
                "evidence": "TCP connection successful",
                "recommendation": "Restrict SSH.",
            }
        ],
    }

    inventory = build_software_inventory(scan_result)

    assert inventory["total_items"] == 1
    assert inventory["items"][0]["service_name"] == "ssh"
    assert inventory["items"][0]["product"] is None
    assert inventory["items"][0]["version"] is None
    assert inventory["items"][0]["source"] == "service_detect"
    assert "service_detect" in inventory["sources_used"]


def test_inventory_handles_missing_product_and_version_safely() -> None:
    scan_result = {
        "host": "demo.local",
        "resolved_ip": "127.0.0.1",
        "open_ports": [
            {
                "host": "demo.local",
                "port": 8080,
                "protocol": "tcp",
                "service": "http-alt",
                "status": "open",
                "confidence": "medium",
                "evidence": "TCP connection successful",
            }
        ],
    }

    item = build_software_inventory(scan_result)["items"][0]

    assert item["service_name"] == "http"
    assert item["product"] is None
    assert item["version"] is None
    assert item["confidence"] == "Medium"


def test_inventory_uses_credentialed_audit_metadata_when_available() -> None:
    scan_result = {
        "host": "demo-windows",
        "resolved_ip": "127.0.0.1",
        "open_ports": [],
        "windows_audit_summary": {
            "enabled": True,
            "status": "success",
            "smb_reachable": True,
            "rdp_reachable": False,
            "winrm_http_reachable": True,
            "winrm_https_reachable": None,
            "windows_host_info_collected": True,
            "windows_host_info": {
                "hostname": "WIN-DEMO-01",
                "os_caption": "Microsoft Windows Server",
                "os_version": "10.0",
            },
        },
    }

    inventory = build_software_inventory(scan_result)
    services = {item["service_name"] for item in inventory["items"]}

    assert {"smb", "winrm"}.issubset(services)
    assert "rdp" not in services
    assert "windows_audit" in inventory["sources_used"]
