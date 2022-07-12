
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

bp = Blueprint('about', __name__)

#Display Data - About
@bp.route('/about')
def index():
    return render_template('about.html')