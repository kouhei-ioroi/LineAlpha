import LineAlpha
from LineAPI.main import qr
cl = LineAlpha.LINE()
cl.login(token=qr().get())
print (cl.token)
