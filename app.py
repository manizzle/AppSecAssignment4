from flask import Flask, render_template, request, redirect, url_for, make_response
import os, os.path
tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "template")
data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
app = Flask(__name__, template_folder=tmpl_dir)
app.secret_key = "shitlick"
import threading
lock = threading.Lock()
import tempfile
import shlex
import subprocess
import hashlib
import os
import time
from flask_sqlalchemy import SQLAlchemy
import datetime

with open("/run/secrets/cookie_secret") as fp:
    secret = fp.read()

user_login = {}
csrf_tok = []

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///local.db'
db = SQLAlchemy(app)

class Queries(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    text = db.Column(db.String(256), nullable=False)
    results = db.Column(db.String(256), nullable=False)

    def __repr__(self):
        return '<User %r Text %r Results %r>' % (self.username, self.text, self.results)

class Logins(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    login = db.Column(db.DateTime, nullable=False)
    logout = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return '<User %r Login %r Logout %r>' % (self.username, self.login, self.logout)

class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(80), nullable=False)
    twofa = db.Column(db.String(80), nullable=True)

    def __repr__(self):
        return '<User %r Pass Hash %r 2FA %r>' % (self.username, self.password, self.twofa)

def setup():
    db.create_all()
    with open("/run/secrets/admin_secret") as fp:
        passw = fp.read()
    row = Registration.query.filter_by(username="admin").first()
    if not row:
        reg = Registration(username="admin", password=hashlib.sha256(passw.encode("utf-8")).hexdigest(), twofa="12345678901")
        db.session.add(reg)
    else:
        row.password = hashlib.sha256(passw.encode("utf-8")).hexdigest()
    db.session.commit()

setup()

@app.route("/history", methods=["GET", "POST"])
def history():
    cookie = request.cookies.get('auth')
    if not cookie:
        return redirect(url_for('login'))
    if cookie not in user_login:
        return redirect(url_for('login'))
    if (time.time() - user_login[cookie]["ts"]) > (60*10):
        return redirect(url_for('login'))

    uname = user_login[cookie]["uname"]

    if uname == "admin":
        if request.method == "POST":
            data = request.form
            if (data["userquery"]):
                if Registration.query.filter_by(username=data["userquery"]).all() == []:
                    return redirect(url_for('history'))
                user_queries = Queries.query.filter_by(username=data["userquery"]).all()
                return render_template("history.html", count=len(user_queries), list_of_items=[u.id for u in user_queries])
            else:
                return redirect(url_for('history'))
        else:
            return render_template("history_admin.html")
    else:
        user_queries = Queries.query.filter_by(username=uname).all()
        return render_template("history.html", count=len(user_queries), list_of_items=[u.id for u in user_queries])

@app.route("/login_history", methods=["GET", "POST"])
def login_history():
    cookie = request.cookies.get('auth')
    if not cookie:
        return redirect(url_for('login'))
    if cookie not in user_login:
        return redirect(url_for('login'))
    if (time.time() - user_login[cookie]["ts"]) > (60*10):
        return redirect(url_for('login'))

    uname = user_login[cookie]["uname"]

    if uname != "admin":
        return redirect(url_for('history'))

    if request.method == "POST":
        data = request.form
        if (data["userid"]):
            if Registration.query.filter_by(username=data["userid"]).all() == []:
                return redirect(url_for('login_history'))
            logins = Logins.query.filter_by(username=data["userid"]).all()
            return render_template("login_results.html", list_of_items=[(l.id, l.login, "N/A" if not l.logout else l.logout) for l in logins])
    else:
        return render_template("login_history.html")

@app.route('/history/query<query_id>')
def profile(query_id):
    cookie = request.cookies.get('auth')
    if not cookie:
        return redirect(url_for('login'))
    if cookie not in user_login:
        return redirect(url_for('login'))
    if (time.time() - user_login[cookie]["ts"]) > (60*10):
        return redirect(url_for('login'))

    uname = user_login[cookie]["uname"]
    query = Queries.query.filter_by(id=query_id).first()
    if (not query or (uname != "admin" and query.username != uname)):
        return redirect(url_for('history'))
    return render_template("query.html", queryid=query_id, username=query.username, querytext=query.text, queryresults=query.results)

@app.route('/')
def root():
    return redirect(url_for('register'))

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        data = request.form
        if (data["uname"] and data["pword"]) and (Registration.query.filter_by(username=data["uname"]).all() == []):
            lock.acquire()
            try:
                reg = Registration(username=data["uname"], password=hashlib.sha256(data["pword"].encode("utf-8")).hexdigest(), twofa=data["2fa"])
                db.session.add(reg)
                db.session.commit()
            finally:
                # Always called, even if exception is raised in try block
                lock.release()
            ret = "success"
        else:
            ret = "failure"
        return render_template("success.html", message=ret)
    else:
        return render_template("login.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        cookie = request.cookies.get('auth')
        if cookie and cookie in user_login:
            uname = user_login[cookie]["uname"]
            del user_login[cookie]  
            row = Logins.query.filter_by(username=uname, logout=None).first()
            if row:
                row.logout = datetime.datetime.now()
                db.session.commit()
        data = request.form

        if (data["uname"] and data["pword"]):
            user = Registration.query.filter_by(username=data["uname"]).first()
            if (user and user.password == hashlib.sha256(data["pword"].encode("utf-8")).hexdigest()):
                ret = "success"
                if user.twofa and user.twofa != data["2fa"]:
                    ret = "Two-factor - failure"
            else:
                ret = "Incorrect"
        else:
            ret = "Incorrect"
        if ret == "success":
            resp = make_response(render_template("success_login.html", message=ret))
            ts = time.time()
            cookie = hashlib.sha256((data["uname"] + data["pword"] + data["2fa"] + str(ts) + secret).encode("utf-8")).hexdigest()
            user_login[cookie] = {"uname": data["uname"], "ts": ts}
            resp.set_cookie('auth', cookie)
            login = Logins(username=data["uname"], login=datetime.datetime.now())
            db.session.add(login)
            db.session.commit()
            return resp
        return render_template("success_login.html", message=ret)
    else:
        cookie = request.cookies.get('auth')
        if cookie and cookie in user_login:
            return render_template("success_login.html", message="success")
        return render_template("login.html")

@app.route("/logout", methods=["GET"])
def logout():
    cookie = request.cookies.get('auth')
    if cookie and cookie in user_login:
        uname = user_login[cookie]["uname"]
        del user_login[cookie]  
        row = Logins.query.filter_by(username=uname, logout=None).first()
        if row:
            row.logout = datetime.datetime.now()
            db.session.commit()
    return redirect(url_for('login'))

@app.route("/spell_check", methods=["GET", "POST"])
def spellcheck():
    cookie = request.cookies.get('auth')
    if not cookie:
        return redirect(url_for('login'))
    if cookie not in user_login:
        return redirect(url_for('login'))
    if (time.time() - user_login[cookie]["ts"]) > (60*10):
        return redirect(url_for('login'))

    if request.method == "POST":

        data = request.form
        csrf_prot = data["csrf-token"]
        if not csrf_prot:
            return redirect(url_for('login'))
        if csrf_prot not in csrf_tok:
            return redirect(url_for('login'))
        csrf_tok.remove(csrf_prot)


        inputdata = ""
        for c in data["inputtext"]:
            if c in ":///\';\"%.?<>()":
                inputdata += "//" + c
            else:
                inputdata += c

        fp = tempfile.NamedTemporaryFile(delete=False)
        if not inputdata:
            return redirect(url_for('spell_check'))
        fp.write(inputdata.encode("utf-8"))
        fp.close()
        cmd = "./a.out %s wordlist.txt"
        args = shlex.split(cmd % fp.name)
        outs, errs = subprocess.Popen(args, stdout=subprocess.PIPE).communicate()
        os.unlink(fp.name)
        if errs:
            return render_template("errors.html")
        #bad_words = ",".join([o.split("misspelled word:")[1] for o in outs.decode("utf-8").splitlines()])
        bad_words = ",".join(outs.decode("utf-8").splitlines())
        query = Queries(username=user_login[cookie]["uname"], text=inputdata, results=bad_words)
        db.session.add(query)
        db.session.commit()
        return render_template("return.html", textout=inputdata, misspelled=bad_words)
    else:
        tok = hashlib.sha256((str(time.time()) + cookie).encode("utf-8")).hexdigest()
        csrf_tok.append(tok)
        return render_template("spellcheck.html", token=tok)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8080, debug=False)