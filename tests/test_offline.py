"""Checks that need no router: framing, redaction, the write tiers, the settings table, read-only mode."""
import asyncio
import os
import struct
import subprocess
import sys
import zlib

from deco_local import tmp, web


def test_tmp_frame_crc():
    body = b'{"x":1}'
    pkt = tmp._tmp_wrap(7, body)
    assert struct.unpack(">H", pkt[4:6])[0] == len(body)
    assert struct.unpack(">I", pkt[8:12])[0] == 7
    crc = struct.unpack(">I", pkt[12:16])[0]
    assert zlib.crc32(pkt[:12] + struct.pack(">I", tmp.CRC_PLACEHOLDER) + pkt[16:]) & 0xFFFFFFFF == crc


def test_redact():
    out = tmp.redact("wifi_bands_info", {"band5": {"host": {"ssid": "home", "password": "s3cret"}}})
    assert out["band5"]["host"] == {"ssid": "home", "password": "***REDACTED***"}
    assert tmp.redact("device_list", {"password": "x"}) == {"password": "x"}  # only listed reads


def test_tiers():
    tiers = {op.tier for op in tmp.WRITE.values()}
    assert tiers <= {"verified", "upstream", "noop", "inferred"}
    assert tmp.WRITE["led_set"].tier == "verified"
    assert tmp.WRITE["homeshield_features_set"].tier == "noop"


def test_settings_point_at_real_ops():
    for name, s in tmp.SETTINGS.items():
        assert s.read in tmp.READ, name
        for w in (s.write, s.add, s.modify, s.remove):
            assert not w or w in tmp.WRITE, (name, w)


def test_web_reads_are_tmp_names():
    assert set(web.WEB_READS) <= set(tmp.READ)


def _tools(readonly):
    code = ("import asyncio, deco_local.mcp_server as m;"
            "print(sorted(t.name for t in asyncio.run(m.server.list_tools())))")
    env = dict(os.environ, DECO_MCP_READONLY="1" if readonly else "")
    return eval(subprocess.check_output([sys.executable, "-c", code], env=env, text=True))


def test_readonly_drops_writes():
    full, ro = _tools(False), _tools(True)
    assert "write_router_setting" in full and "get_router_data_unredacted" in full
    assert set(ro) == {"list_reads", "get_router_data", "mesh_overview", "lockout_status"}


def test_web_snapshot_rotates_node_probes(tmp_path, monkeypatch):
    """Which node a client is on costs a request per node: only `probes` nodes are re-asked per call."""
    import contextlib
    monkeypatch.setenv("DECO_STATE_DIR", str(tmp_path))
    asked = []

    class Fake:
        def devices(self):
            return [{"mac": f"N{i}", "device_id": f"id{i}", "role": "master" if i == 0 else "slave",
                     "group_status": "connected"} for i in range(4)]

        def clients(self):
            return [{"mac": "C1", "connection_type": "band5"}]

        def read(self, path, params=None):
            asked.append(params["device_mac"])
            return {"client_list": [{"mac": "C1"}] if params["device_mac"] == "N2" else []}

    @contextlib.contextmanager
    def fake_session(host, password):
        yield Fake()

    monkeypatch.setattr(web, "session", fake_session)
    snap = web.snapshot("h", "p", ["client_list"], gap=0, probes=2)
    assert asked == ["N0", "N1", "N2", "N3"]  # first call builds the whole map
    assert snap["client_list"]["result"]["client_list"][0]["linked_device_info"]["device_id"] == "id2"
    asked.clear()
    web.snapshot("h", "p", ["client_list"], gap=0, probes=2)
    assert asked == ["N0", "N1"]
    asked.clear()
    snap = web.snapshot("h", "p", ["client_list"], gap=0, probes=2)
    assert asked == ["N2", "N3"]
    assert snap["client_list"]["result"]["client_list"][0]["linked_device_info"]["device_id"] == "id2"
