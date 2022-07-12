
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

bp = Blueprint('testimonials', __name__)

#Display Data - About
@bp.route('/testimonials')
def index():
    return render_template('testimonials.html')