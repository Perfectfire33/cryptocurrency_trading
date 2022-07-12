from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from werkzeug.exceptions import abort

from flaskr.auth import login_required
from flaskr.db import get_db
import os

bp = Blueprint('blog', __name__)


@bp.route('/blog')
def index():
    db = get_db()
    posts = db.execute(
        'SELECT p.post_id, post_title, post_body, post_shortbody, post_images, post_created, post_author_id, xuser_username'
        ' FROM post p JOIN xuser u ON p.post_author_id = u.xuser_id'
        ' ORDER BY post_created DESC'
    ).fetchall()

    #print("AAAAAAAAAAAAAA")
    #print(posts[0][4])
    #print("AAAAAAAAAAAAAA")
    return render_template('blog/index.html', posts=posts)



@bp.route('/upload/<filename>')
def send_uploaded_file(filename=''):
    from flask import send_from_directory
    dirname = os.path.dirname(__file__)
    upload_folder = os.path.join(dirname, 'upload')
    return send_from_directory(upload_folder, filename)

@bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if request.method == 'POST':
        #upload_folder = './flaskr/upload/'
        #upload_folder = '//upload//'
        dirname = os.path.dirname(__file__)
        #print("AAAAAAAAA")
        #print(dirname)
        #print("AAAAAAAAA")
        upload_folder = os.path.join(dirname, 'upload')
        #print("BBBBBBB")
        #print(upload_folder)
        #print("BBBBBBB")

        #upload_folder = 'c:/Users/Joseph/Documents/GitHub/openhouseparty.online/flaskr/upload'
        #if "file1" not in request.files:
        #    return "there is no file1 in form!"
        file1 = request.files["file1"]
        if file1.filename != '':
            path = os.path.join(upload_folder, file1.filename)
            file1.save(path)

            title = request.form['title']
            body = request.form['body']
            error = None
            short_body = body[0:100]

            if not title:
                error = 'Title is required.'

            if error is not None:
                flash(error)
            else:
                db = get_db()
                db.execute(
                    'INSERT INTO post (post_title, post_body, post_shortbody, post_images, post_author_id)'
                    ' VALUES (?, ?, ?, ?, ?)',
                    (title, body, short_body, file1.filename, g.user['xuser_id'])
                )
                db.commit()
                return redirect(url_for('blog.index'))

        else:
            title = request.form['title']
            body = request.form['body']
            error = None
            short_body = body[0:100]

            if not title:
                error = 'Title is required.'

            if error is not None:
                flash(error)
            else:
                db = get_db()
                db.execute(
                    'INSERT INTO post (post_title, post_body, post_shortbody, post_author_id)'
                    ' VALUES (?, ?, ?, ?)',
                    (title, body, short_body, g.user['xuser_id'])
                )
                db.commit()
                return redirect(url_for('blog.index'))


    return render_template('blog/create.html')


def get_post(id, check_author=True):
    post = get_db().execute(
        'SELECT p.post_id, post_title, post_body, post_created, post_images, post_author_id, xuser_username'
        ' FROM post p JOIN xuser u ON p.post_author_id = u.xuser_id'
        ' WHERE p.post_id = ?',
        (id,)
    ).fetchone()

    if post is None:
        abort(404, f"Post id {id} doesn't exist.")

    if check_author and post['post_author_id'] != g.user['xuser_id']:
        abort(403)

    return post


def get_post_view(id):
    post = get_db().execute(
        'SELECT p.post_id, post_title, post_body, post_created, post_images, post_author_id, xuser_username'
        ' FROM post p JOIN xuser u ON p.post_author_id = u.xuser_id'
        ' WHERE p.post_id = ?',
        (id,)
    ).fetchone()

    if post is None:
        abort(404, f"Post id {id} doesn't exist.")

    return post

@bp.route('/<int:id>/view', methods=('GET', 'POST'))
def view(id):
    post = get_post_view(id)

    return render_template('blog/view_post.html', post=post)


@bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    post = get_post(id)

    if request.method == 'POST':
        title = request.form['title']
        body = request.form['body']
        error = None
        short_body = body[0:100]

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE post SET post_title = ?, post_shortbody = ?, post_body = ?'
                ' WHERE post_id = ?',
                (title, body, short_body, id)
            )
            db.commit()
            return redirect(url_for('blog.index'))

    return render_template('blog/update.html', post=post)


@bp.route('/<int:id>/delete', methods=('POST',))
@login_required
def delete(id):
    post = get_post(id)

    dirname = os.path.dirname(__file__)
    upload_folder = os.path.join(dirname, 'upload')
    file_to_delete = os.path.join(upload_folder, post['post_images'])
    os.remove(file_to_delete)



    db = get_db()
    db.execute('DELETE FROM post WHERE post_id = ?', (id,))
    db.commit()
    return redirect(url_for('blog.index'))

