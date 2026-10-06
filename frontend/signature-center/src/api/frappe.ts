import axios from "axios"

const api = axios.create({
  baseURL: "/api",
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
})

export async function getResource(
  doctype: string,
  params: Record<string, unknown> = {},
) {
  const res = await api.get(
    "/resource/" + encodeURIComponent(doctype),
    { params },
  )

  return res.data.data
}

export async function callMethod(
  method: string,
  args: Record<string, unknown> = {},
) {
  const res = await api.post("/method/" + method, args)

  return res.data.message
}

export async function getCurrentUser() {
  return await callMethod("frappe.auth.get_logged_user")
}

export default api
