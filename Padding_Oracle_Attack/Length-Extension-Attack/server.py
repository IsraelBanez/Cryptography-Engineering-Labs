import web, urllib.parse
import crypto

mac = crypto.KeyedMAC()
render = web.template.render('templates/')
urls = ('/', 'index',
        '/post', 'post')

#This is all stuff to fake a database
posts = []
post_counter = 0
all_posts = []
f = open("static/whosonfirst.txt", "r")
for l in f:
    who,what = l.split(":")
    all_posts.append([who, what[:-1], mac.mac_post(what[:-1])])

class index:

    #Handle both GETs and POSTs
    #GETs the who, what, and mac are key-value query parameters in the URL
    #POSTs the who, what, and mac are key-value parameters in tht HTTP header

    def POST(self):
        user_data = web.input(who="",what="",mac="",_unicode=True)

        if user_data.who == "" or user_data.what == "" or user_data.mac == "":
            if post_counter > 0:
                return render.generic(posts, "Invalid post.")
            else:
                return render.generic(posts, "")
        try:
            #Make sure the mac is hex-encoded
            int(user_data.mac, 16)
        except:
            return render.generic(posts, "Signature must be in hex.")

        if mac.verify_post(urllib.parse.unquote_to_bytes(user_data.what), user_data.mac):
            try:
                #Sometimes we get weird chracters, percent quote them
                #if they're not unicode.
                unicode(user_data.what)
            except:
                user_data.what = urllib.parse.quote(user_data.what)
            
            #Update our posts "database"
            posts.append([user_data.who,  urllib.parse.unquote(user_data.what), user_data.mac])
            return render.generic(posts, "")
        else:
            return render.generic(posts, "Invalid signature.")

    def GET(self):
        user_data = web.input(who="",what="",mac="",_unicode=True)

        if user_data.who == "" or user_data.what == "" or user_data.mac == "":
            if post_counter > 0:
                return render.generic(posts, "Invalid post.")
            else:
                return render.generic(posts, "")
        try:
            #Make sure the mac is hex-encoded
            int(user_data.mac, 16)
        except:
            return render.generic(posts, "Signature must be in hex.")

        if mac.verify_post(urllib.parse.unquote_to_bytes(user_data.what), user_data.mac):
            try:
                #Sometimes we get weird chracters, percent quote them
                #if they're not unicode.
                unicode(user_data.what)
            except:
                user_data.what = urllib.parse.quote(user_data.what)
            
            #Update our posts "database"
            posts.append([user_data.who,  urllib.parse.unquote(user_data.what), user_data.mac])
            return render.generic(posts, "")
        else:
            return render.generic(posts, "Invalid signature.")
            
class post:
    def GET(self):
        #Create a fake post to our forum
        global post_counter
        who, what, mac = all_posts[post_counter]
        post_counter = (post_counter + 1)%len(all_posts)
        raise web.seeother("/?who=" + who + "&what=" + what + "&mac=" + mac)

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()