from aiohttp import ClientSession
from fastapi import FastAPI, HTTPException, Request, Response
import json

app = FastAPI(docs_url=None, redoc_url=None)


def _filter_happ_headers(headers):
    keys = ["user-agent", "x-app-version", "x-device-locale", "x-device-os", "x-device-model", "x-ver-os", "x-hwid"]
    return {name: value for name, value in headers.items() if name in keys}


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
        return json.loads(content), True
    except json.JSONDecodeError:
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
                "domain:github.com",
                "domain:githubassets.com",
                "domain:todoist.com"
            ],
            "outboundTag": "direct"
        },
        {
            "type": "field",
            "domain": [
                "regexp:\\.ru$",
                "regexp:\\.рф$"
            ],
            "outboundTag": "direct"
        },
        {
            "type": "field",
            "ip": [
                "geoip:ru",
                "ip:10.90.25.12"
            ],
            "outboundTag": "direct"
        }
    ]

    subscription = []

    for server in origin_subscription:
        # if server["remarks"] in allowed_remarks:
        if True:
            server["routing"]["rules"] = rules + server["routing"]["rules"]
            subscription.append(server)

    return subscription


def _filter_spam(request: Request):
    allowed_agents = ["happ", "incy"]

    if not any(agent in request.headers.get("user-agent", "").lower() for agent in allowed_agents):
        raise HTTPException(status_code=403, detail="Forbidden")


@app.get("/{sub}")
async def read_root(request: Request, sub: str):
    _filter_spam(request)

    input_headers = _filter_happ_headers(request.headers)

    content, headers, status = await _get_subscription(input_headers, sub)

    print(headers)

    subscription, is_json = _try_parse_json(content)

    if not is_json:
        return Response(
            content=content,
            status_code=status,
            headers=headers,
        )
    else:
        subscription = _reassemble_happ_subscription(subscription)

        return Response(
            content=json.dumps(subscription),
            status_code=status,
            headers=headers,
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
