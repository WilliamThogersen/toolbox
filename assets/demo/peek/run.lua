return function()
  local key = vault("demo")
  local res = http.get("https://httpbin.org/headers", {
    headers = { Authorization = "Bearer " .. key },
  })
  return {
    script_sees = key,
    server_echoed = res.json.headers.Authorization,
  }
end
