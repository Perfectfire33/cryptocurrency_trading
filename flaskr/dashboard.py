
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from flaskr.auth import login_required

bp = Blueprint('dashboard', __name__)

#Display Data - Dashboard
@bp.route('/dashboard')
@login_required
def index():
    return render_template('dashboard.html')