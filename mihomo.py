import urllib.parse
import yaml


def outbound_to_uri(ob: dict, default_name: str) -> str:
    tag = ob.get("tag", "proxy")
    proto = ob.get("protocol")
    settings = ob.get("settings", {})
    stream_settings = ob.get("streamSettings", {})
    name = tag if tag and tag != "proxy" else default_name

    if proto == "vless":
        vnext = settings.get("vnext", [{}])[0]
        addr = vnext.get("address")
        port = vnext.get("port")
        users = vnext.get("users", [{}])[0]
        uuid = users.get("id")
        flow = users.get("flow", "")
        encryption = users.get("encryption", "none")

        if not uuid or not addr or not port or addr == "120":
            return ""

        params = {}
        if encryption:
            params["encryption"] = encryption
        if flow:
            params["flow"] = flow

        net = stream_settings.get("network", "tcp")
        params["type"] = net

        sec = stream_settings.get("security", "none")
        params["security"] = sec

        if sec == "reality":
            r_settings = stream_settings.get("realitySettings", {})
            if "serverName" in r_settings:
                params["sni"] = r_settings["serverName"]
            if "publicKey" in r_settings:
                params["pbk"] = r_settings["publicKey"]
            if "shortId" in r_settings:
                params["sid"] = r_settings["shortId"]
            if "fingerprint" in r_settings:
                params["fp"] = r_settings["fingerprint"]
        elif sec == "tls":
            t_settings = stream_settings.get("tlsSettings", {})
            if "serverName" in t_settings:
                params["sni"] = t_settings["serverName"]
            if "fingerprint" in t_settings:
                params["fp"] = t_settings["fingerprint"]
            if "alpn" in t_settings and t_settings["alpn"]:
                params["alpn"] = ",".join(t_settings["alpn"])

        if net == "grpc":
            g_settings = stream_settings.get("grpcSettings", {})
            if "serviceName" in g_settings:
                params["serviceName"] = g_settings["serviceName"]
            if "authority" in g_settings and g_settings["authority"]:
                params["authority"] = g_settings["authority"]
            if g_settings.get("mode"):
                params["mode"] = "multi"

        query_str = urllib.parse.urlencode(params)
        return f"vless://{uuid}@{addr}:{port}?{query_str}#{urllib.parse.quote(name)}"

    elif proto == "trojan":
        servers = settings.get("servers", [{}])[0]
        addr = servers.get("address")
        port = servers.get("port")
        password = servers.get("password")

        if not password or not addr or not port or addr == "120":
            return ""

        params = {}
        sec = stream_settings.get("security", "tls")
        params["security"] = sec

        t_settings = stream_settings.get("tlsSettings", {}) or stream_settings.get("realitySettings", {})
        if "serverName" in t_settings:
            params["sni"] = t_settings["serverName"]
        if "fingerprint" in t_settings:
            params["fp"] = t_settings["fingerprint"]
        if "alpn" in t_settings and t_settings["alpn"]:
            params["alpn"] = ",".join(t_settings["alpn"])

        net = stream_settings.get("network", "tcp")
        params["type"] = net

        query_str = urllib.parse.urlencode(params)
        return f"trojan://{password}@{addr}:{port}?{query_str}#{urllib.parse.quote(name)}"

    elif proto == "shadowsocks":
        servers = settings.get("servers", [{}])[0]
        addr = servers.get("address")
        port = servers.get("port")
        password = servers.get("password")
        method = servers.get("method", "chacha20-ietf-poly1305")

        if not password or not addr or not port or addr == "120":
            return ""

        userpass = f"{method}:{password}"
        userpass_b64 = urllib.parse.quote(userpass)
        return f"ss://{userpass_b64}@{addr}:{port}#{urllib.parse.quote(name)}"

    elif proto in ("hysteria", "hysteria2", "hy2"):
        hy_settings = stream_settings.get("hysteriaSettings", {}) or settings
        addr = settings.get("address")
        port = settings.get("port")
        auth = hy_settings.get("auth") or settings.get("auth") or settings.get("password")

        if not auth or not addr or not port or addr == "120":
            return ""

        params = {}
        t_settings = stream_settings.get("tlsSettings", {})
        if "serverName" in t_settings:
            params["sni"] = t_settings["serverName"]
        if "fingerprint" in t_settings:
            params["fp"] = t_settings["fingerprint"]

        finalmask = stream_settings.get("finalmask", {})
        udp_masks = finalmask.get("udp", [])
        if udp_masks:
            mask = udp_masks[0]
            if mask.get("type"):
                params["obfs"] = mask.get("type")
            if mask.get("settings", {}).get("password"):
                params["obfs-password"] = mask.get("settings", {}).get("password")

        query_str = urllib.parse.urlencode(params)
        return f"hy2://{auth}@{addr}:{port}?{query_str}#{urllib.parse.quote(name)}"

    return ""


def convert_to_uri_links(origin_subscription: list) -> str:
    links = []
    for idx, profile in enumerate(origin_subscription, 1):
        remark = profile.get("remarks", f"Server-{idx}")
        outbounds = profile.get("outbounds", [])
        proxy_obs = [ob for ob in outbounds if ob.get("tag") not in ("direct", "block")]

        for ob in proxy_obs:
            orig_tag = ob.get("tag", "proxy")
            node_name = f"{remark} [{orig_tag}]" if len(proxy_obs) > 1 else remark
            uri = outbound_to_uri(ob, node_name)
            if uri:
                links.append(uri)

    return "\n".join(links)


def outbound_to_mihomo_proxy(ob: dict, node_name: str) -> dict:
    proto = ob.get("protocol")
    settings = ob.get("settings", {})
    stream_settings = ob.get("streamSettings", {})
    name = node_name

    if proto == "vless":
        vnext = settings.get("vnext", [{}])[0]
        addr = vnext.get("address")
        port = vnext.get("port")
        users = vnext.get("users", [{}])[0]
        uuid = users.get("id")
        flow = users.get("flow", "")
        encryption = users.get("encryption", "none")

        if not uuid or not addr or not port or addr == "120":
            return None

        proxy = {
            "name": name,
            "type": "vless",
            "server": addr,
            "port": int(port),
            "uuid": uuid,
            "cipher": encryption if encryption and encryption != "none" else "auto",
            "udp": True,
        }

        if flow:
            proxy["flow"] = flow

        net = stream_settings.get("network", "tcp")
        proxy["network"] = net

        sec = stream_settings.get("security", "none")
        if sec in ("reality", "tls"):
            proxy["tls"] = True
            if sec == "reality":
                r_settings = stream_settings.get("realitySettings", {})
                if "serverName" in r_settings:
                    proxy["servername"] = r_settings["serverName"]
                if "publicKey" in r_settings or "shortId" in r_settings:
                    r_opts = {}
                    if "publicKey" in r_settings:
                        r_opts["public-key"] = r_settings["publicKey"]
                    if "shortId" in r_settings:
                        r_opts["short-id"] = r_settings["shortId"]
                    proxy["reality-opts"] = r_opts
                if "fingerprint" in r_settings:
                    proxy["client-fingerprint"] = r_settings["fingerprint"]
            elif sec == "tls":
                t_settings = stream_settings.get("tlsSettings", {})
                if "serverName" in t_settings:
                    proxy["servername"] = t_settings["serverName"]
                if "fingerprint" in t_settings:
                    proxy["client-fingerprint"] = t_settings["fingerprint"]
                if "alpn" in t_settings and t_settings["alpn"]:
                    proxy["alpn"] = t_settings["alpn"]

        if net == "grpc":
            g_settings = stream_settings.get("grpcSettings", {})
            if "serviceName" in g_settings:
                proxy["grpc-opts"] = {"grpc-service-name": g_settings["serviceName"]}
        elif net == "ws":
            w_settings = stream_settings.get("wsSettings", {})
            ws_opts = {}
            if "path" in w_settings:
                ws_opts["path"] = w_settings["path"]
            if "headers" in w_settings:
                ws_opts["headers"] = w_settings["headers"]
            if ws_opts:
                proxy["ws-opts"] = ws_opts

        return proxy

    elif proto == "trojan":
        servers = settings.get("servers", [{}])[0]
        addr = servers.get("address")
        port = servers.get("port")
        password = servers.get("password")

        if not password or not addr or not port or addr == "120":
            return None

        proxy = {
            "name": name,
            "type": "trojan",
            "server": addr,
            "port": int(port),
            "password": password,
            "udp": True,
        }

        sec = stream_settings.get("security", "tls")
        if sec in ("tls", "reality"):
            t_settings = stream_settings.get("tlsSettings", {}) or stream_settings.get("realitySettings", {})
            if "serverName" in t_settings:
                proxy["sni"] = t_settings["serverName"]
            if "fingerprint" in t_settings:
                proxy["client-fingerprint"] = t_settings["fingerprint"]
            if "alpn" in t_settings and t_settings["alpn"]:
                proxy["alpn"] = t_settings["alpn"]

        net = stream_settings.get("network", "tcp")
        proxy["network"] = net
        return proxy

    elif proto == "shadowsocks":
        servers = settings.get("servers", [{}])[0]
        addr = servers.get("address")
        port = servers.get("port")
        password = servers.get("password")
        method = servers.get("method", "chacha20-ietf-poly1305")

        if not password or not addr or not port or addr == "120":
            return None

        return {
            "name": name,
            "type": "ss",
            "server": addr,
            "port": int(port),
            "cipher": method,
            "password": password,
            "udp": True,
        }

    elif proto in ("hysteria", "hysteria2", "hy2"):
        hy_settings = stream_settings.get("hysteriaSettings", {}) or settings
        addr = settings.get("address")
        port = settings.get("port")
        auth = hy_settings.get("auth") or settings.get("auth") or settings.get("password")

        if not auth or not addr or not port or addr == "120":
            return None

        proxy = {
            "name": name,
            "type": "hysteria2",
            "server": addr,
            "port": int(port),
            "password": auth,
            "udp": True,
        }

        t_settings = stream_settings.get("tlsSettings", {})
        if "serverName" in t_settings:
            proxy["sni"] = t_settings["serverName"]
        if "fingerprint" in t_settings:
            proxy["client-fingerprint"] = t_settings["fingerprint"]
        if "alpn" in t_settings and t_settings["alpn"]:
            proxy["alpn"] = t_settings["alpn"]

        finalmask = stream_settings.get("finalmask", {})
        udp_masks = finalmask.get("udp", [])
        if udp_masks:
            mask = udp_masks[0]
            if mask.get("type"):
                proxy["obfs"] = mask.get("type")
            if mask.get("settings", {}).get("password"):
                proxy["obfs-password"] = mask.get("settings", {}).get("password")

        return proxy

    return None


def convert_to_mihomo_yaml(origin_subscription: list) -> str:
    all_proxies = []
    group_nodes = {
        "Balancer": [],
        "Auto": [],
        "Bypass": [],
        "VPN": [],
    }
    current_group = "Balancer"

    for idx, profile in enumerate(origin_subscription, 1):
        remark = profile.get("remarks", f"Server-{idx}")

        if "⚡⚡⚡Самые быстрые" in remark:
            current_group = "Auto"
            continue
        elif "🧊Свежие резервы" in remark:
            current_group = "Bypass"
            continue
        elif "💥Сервера под VPN" in remark or "Сервера под VPN" in remark:
            current_group = "VPN"
            continue

        outbounds = profile.get("outbounds", [])
        proxy_obs = [ob for ob in outbounds if ob.get("tag") not in ("direct", "block")]

        for ob in proxy_obs:
            orig_tag = ob.get("tag", "proxy")
            node_name = f"{remark} [{orig_tag}]" if len(proxy_obs) > 1 else remark
            p_dict = outbound_to_mihomo_proxy(ob, node_name)
            if p_dict:
                all_proxies.append(p_dict)
                group_nodes[current_group].append(node_name)

    full_config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "external-controller": "127.0.0.1:9090",
        "authentication": [
            "admin:secretpassword123",
        ],
        "dns": {
            "enable": True,
            "ipv6": False,
            "default-nameserver": ["1.1.1.1", "8.8.8.8"],
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "nameserver": ["https://dns.adguard-dns.com/dns-query", "1.1.1.1"],
        },
        "proxies": all_proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["Fallback", "Balancer", "Auto", "Bypass", "VPN", "DIRECT"],
            },
            {
                "name": "Fallback",
                "type": "fallback",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": ["Auto", "VPN", "Bypass", "Balancer"],
            },
            {
                "name": "Balancer",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": group_nodes["Balancer"] if group_nodes["Balancer"] else ["DIRECT"],
            },
            {
                "name": "Auto",
                "type": "select",
                "proxies": group_nodes["Auto"] if group_nodes["Auto"] else ["DIRECT"],
            },
            {
                "name": "Bypass",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": group_nodes["Bypass"] if group_nodes["Bypass"] else ["DIRECT"],
            },
            {
                "name": "VPN",
                "type": "select",
                "proxies": group_nodes["VPN"] if group_nodes["VPN"] else ["DIRECT"],
            },
        ],
        "rules": [
            "GEOSITE,category-ads-all,REJECT",
            "GEOSITE,category-gov-ru,DIRECT",
            "GEOSITE,category-ru,DIRECT",
            "GEOIP,RU,DIRECT",
            "GEOIP,LAN,DIRECT",
            "MATCH,PROXY",
        ],
    }

    return yaml.dump(full_config, allow_unicode=True, sort_keys=False)
