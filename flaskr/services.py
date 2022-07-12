
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

bp = Blueprint('services', __name__)

#Display Data - About
@bp.route('/services')
def index():
    return render_template('services.html')