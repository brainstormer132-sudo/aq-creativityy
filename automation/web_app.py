from flask import Flask, render_template, redirect
import sqlite3

# IMPORTANT
from contract_generator import generate_contract_from_gui

app = Flask(__name__)


DB_PATH = "contract_suite.db"


# CONNECT DATABASE
def get_db():

    conn = sqlite3.connect(DB_PATH)

    conn.row_factory = sqlite3.Row

    return conn


# DASHBOARD
@app.route("/")
def dashboard():

    conn = sqlite3.connect("contract_suite.db")
    conn.row_factory = sqlite3.Row

    tasks = conn.execute("SELECT * FROM tasks").fetchall()

    return render_template("dashboard.html", tasks=tasks)



# GENERATE CONTRACT
@app.route("/generate/<task_id>")
def generate(task_id):

    db = get_db()

    task = db.execute(

        "SELECT * FROM tasks WHERE id=?",

        (task_id,)

    ).fetchone()


    subtasks = db.execute(

        "SELECT * FROM subtasks WHERE task_id=?",

        (task_id,)

    ).fetchall()


    for sub in subtasks:


        context = {

            "brand_name": task["brand"],

            "amount": task["amount"],

            "contract_type": task["contract_type"],

            "channel_name": sub["channel"],

            "platform": sub["platforms"],

            "ad_types": sub["ad_type"],

            "influencer_name_as_per_license": sub["vendor"],

            "license_number": "",

            "city_as_per_license": "",

            "neighbourhood_as_per_license": "",

            "bank_name": "",

            "account_name": "",

            "iban": "",

            "account_number": "",

            "swift_code": "",

        }


        generate_contract_from_gui(context)


    return redirect("/")



# START SERVER
if __name__ == "__main__":

    app.run(debug=True)
