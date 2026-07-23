import json
from aiohttp import ClientSession
from fastapi import FastAPI, HTTPException, Request, Response

from mihomo import convert_to_mihomo_yaml, convert_to_uri_links

app = FastAPI(docs_url=None, redoc_url=None)


def _filter_happ_headers(headers):
    keys = ["user-agent", "x-app-version", "x-device-locale", "x-device-os", "x-device-model", "x-ver-os", "x-hwid"]
    return {name: value for name, value in headers.items() if name.lower() in keys}


async def _get_subscription(headers, sub) -> tuple[bytes, dict, int]:
    async with ClientSession() as session:
        async with session.get(f"https://oversub.cloud/{sub}", headers=headers) as response:
            return await response.read(), _process_oversub_headers(dict(response.headers)), response.status


def _process_oversub_headers(headers) -> dict:
    headers["Announce"] = "base64:8J+QiOKAjeKsmyBPdmVyU2VjdXJlIFZQTiB3aXRoIGlubm9wb2xpcyByb3V0aW5n"
    headers["Profile-Title"] = "base64:8J+QiOKAjeKsmyBPdmVyU2VjdXJlIFZQTg=="
    if "Server" in headers:
        del headers["Server"]
    if "Content-Encoding" in headers:
        del headers["Content-Encoding"]

    return headers


def _try_parse_json(content) -> tuple[list, bool]:
    try:
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="ignore")
        return json.loads(content), True
    except (json.JSONDecodeError, TypeError):
        return content, False


def _reassemble_happ_subscription(origin_subscription: list) -> list:
    rules = [
        {
            "type": "field",
            "domain": [
                "domain:innohassle.ru",
                "domain:innopolis.university",
                "domain:innopolis.ru",
                "domain:dofi4ka.ru",
                "domain:duckduckgo.com",
                "domain:perplexity.ai",
                "domain:todoist.com",
            ],
            "outboundTag": "direct",
        },
        {
            "type": "field",
            "domain": ["regexp:\\.ru$", "regexp:\\.рф$"],
            "outboundTag": "direct",
        },
        {
            "type": "field",
            "ip": ["geoip:ru", "geoip:private"],
            "outboundTag": "direct",
        },
    ]

    subscription = []
    for server in origin_subscription:
        server["routing"]["rules"] = rules + server["routing"]["rules"]
        subscription.append(server)

    return subscription


def _check_user_agent(request: Request) -> str:
    ua = request.headers.get("user-agent", "").lower()
    if any(agent in ua for agent in ["happ", "incy"]):
        return "happ"
    elif "saywallahi" in ua:
        return "saywallahi"
    elif any(agent in ua for agent in ["mihomo", "clash.meta", "clash"]):
        return "mihomo"
    return None


@app.get("/{sub}")
async def read_root(request: Request, sub: str):
    client_type = _check_user_agent(request)
    if not client_type:
        raise HTTPException(status_code=403, detail="Forbidden")

    if client_type == "happ":
        input_headers = _filter_happ_headers(request.headers)
    else:
        input_headers = {"User-Agent": "Happ/3.17.0/Android/1775650247711753599"}

    content, headers, status = await _get_subscription(input_headers, sub)
    subscription, is_json = _try_parse_json(content)

    if not is_json:
        return Response(
            content=content,
            status_code=status,
            headers=headers,
        )

    subscription = _reassemble_happ_subscription(subscription)

    if client_type == "happ":
        return Response(
            content=json.dumps(subscription),
            status_code=status,
            headers=headers,
        )

    elif client_type == "saywallahi":
        uri_links_text = convert_to_uri_links(subscription)
        headers["Content-Type"] = "text/plain; charset=utf-8"
        return Response(
            content=uri_links_text,
            status_code=status,
            headers=headers,
            media_type="text/plain",
        )

    elif client_type == "mihomo":
        yaml_content = convert_to_mihomo_yaml(subscription)
        headers["Content-Type"] = "text/yaml; charset=utf-8"
        return Response(
            content=yaml_content,
            status_code=status,
            headers=headers,
            media_type="text/yaml",
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
