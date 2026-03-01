"""About page route."""

from flask import Blueprint, render_template

from auth import login_required

about_bp = Blueprint("about", __name__)


@about_bp.route("/about")
@login_required
def index():
    """Render the About page."""
    return render_template("about.html")
