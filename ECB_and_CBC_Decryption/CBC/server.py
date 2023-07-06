import web
from web import form
import crypto, hashlib, os

STR_COOKIE_NAME = "auth_token"

master_key = os.urandom(16)

#Database of users. Key is username, value is [SHA1(password), userid, role]
user_db = {"admin":["119ba0f0a97158cd4c92f9ee6cf2f29e75f5e05a", 0, "admin"]}
user_ids = int(1)

render = web.template.render('templates/')
urls = ('/', 'index', 
		'/register', 'register',
		'/logout', 'logout',
		'/home', 'home')

class index:
	login_form = form.Form(
		form.Textbox("user",
			form.notnull,
			description="Username",
			id='usernameBox'),
		form.Password("password",
			form.notnull,
			description="Password",
			id='passwordBox'),
		form.Button("Login",
			id='loginButton'))

	nullform = form.Form()

	def GET(self):
		user, uid, role = verify_cookie()
		if user != "":
			return render.login(self.nullform, user, "Already logged in.")

		return render.login(self.login_form(), "", "")

	def POST(self):
		form = self.login_form()

		if not form.validates():
			return render.login(form, "", "Invalid form data.")

		user = form.d.user
		pw = hashlib.sha1(form.d.password.encode("UTF-8")).hexdigest()

		if user in user_db and user_db[user][0] == pw:
			create_cookie(user, user_db[user][1], user_db[user][2])
			raise web.seeother('/home')
		
		return render.login(form, "", "Username/Password Incorrect")


class register:
	myform = form.Form(
		form.Textbox("user",
			form.notnull,
			description = "Username"),
		form.Password("password",
			form.notnull,
			description = "Password"),
		form.Button("Register",
			description="Register"))

	nullform = form.Form()

	def GET(self):
		user, uid, role = verify_cookie()
		if user != "":
			return render.generic(self.nullform, user, "", "Already logged in.")

		return render.generic(self.myform(), "", "Enter a username and password.", "")
		

	def POST(self):
		global user_ids
		form = self.myform()
		msg = ""
		err = ""
		
		if not form.validates():
			err = "Invalid fields."
		else:
			if form.d.user in user_db:
				err = "User already registered."
			else:
				#Set the password and role: only non-admin "users" can be created
				#through the web interface
				user_db[form.d.user] = [hashlib.sha1(form.d.password.encode("UTF-8")).hexdigest(), user_ids, "user"]
				user_ids += 1
				msg = "User registered."
		return render.generic(self.nullform(), "", msg, err)

class logout:
	def GET(self):
		destroy_cookie()
		raise web.seeother('/')

class home:

	def GET(self):
		user, uid, role = verify_cookie()
		
		#Don't really need to check UID, if user and role checks out.
		if user == "":
			return render.home("", "", "", "Please log in.")
		elif role == "admin":
			msg = "Welcome, Admin!"
		else:
			msg = "Welcome, " + user

		return render.home(user, role, msg, "")

def destroy_cookie():
	web.setcookie(STR_COOKIE_NAME, "", expires=-1)
	
def create_cookie(user, uid, role):
	cookie = crypto.create_crypto_cookie(user, uid, role, master_key)
	web.setcookie(STR_COOKIE_NAME, cookie.hex())

def verify_cookie():
    cookie = web.cookies().get(STR_COOKIE_NAME)
    if cookie == None:
        return "","",""
    try:
        return crypto.verify_crypto_cookie(bytes.fromhex(cookie), master_key)
    except:
        return "","",""

if __name__ == "__main__":
	app = web.application(urls, globals())
	app.run()
