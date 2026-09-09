def csrf_post(client, path, **kwargs):
    client.get("/")
    with client.session_transaction() as session:
        token = session["csrf_token"]
    data = dict(kwargs.pop("data", {}))
    data["csrf_token"] = token
    return client.post(path, data=data, **kwargs)
