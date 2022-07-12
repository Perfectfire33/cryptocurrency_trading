
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
# import smtplib
from flaskr.db import get_db

bp = Blueprint('contact_us', __name__)

#Display Data - About
@bp.route('/contact_us', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':

        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        body = request.form['body']

        #message = "Thank you!"

        #server = smtplib.SMTP("smtp.gmail.com", 587)
        #server.starttls()
        # set environmental variable here for password
        #server.login('chas@gmail.com', 'password')
        #send email from server to person who filled out the contact us form
        #server.sendmail('chas@gmail.com', email, message)
        error = None
        db = get_db()
        if not name:
            error = 'Name is required.'
        elif not email:
            error = 'Email is required.'
        elif not subject:
            error = 'Subject is required.'
        elif not body:
            error = 'Message body is required.'

        if error is None:
                db.execute(
                    'INSERT INTO message (message_name, message_email, message_subject, message_body) VALUES (?, ?, ?, ?)',
                    [name, email, subject, body]
                )
                db.commit()

                return render_template('home.html')
        else:
                flash(error)


    return render_template('contact_us.html')


#create messages within the flaskr app: messages from people filling out contact_us form
#add a new message to the sqlite database when a user hits submit on the web form
#this way, we don't need to send an email from chas@gmail.com to chas@gmail.com essentially