
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

bp = Blueprint('home', __name__)

#Display Data - Dashboard
@bp.route('/')
def index():
    return render_template('home.html')