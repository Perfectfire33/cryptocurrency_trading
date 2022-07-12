
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

bp = Blueprint('resources', __name__)

#Display Data - Dashboard
@bp.route('/resources')
def index():
    return render_template('resources.html')