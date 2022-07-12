
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

bp = Blueprint('store', __name__)

#Display Data - Dashboard
@bp.route('/store')
def index():
    return render_template('store.html')