
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)

bp = Blueprint('faq', __name__)

#Display Data - Dashboard
@bp.route('/faq')
def index():
    return render_template('faq.html')