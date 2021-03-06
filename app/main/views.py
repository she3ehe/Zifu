import os
from flask import render_template, redirect, url_for, abort, flash, request,\
    current_app, make_response
from flask.ext.login import login_required, current_user
from flask.ext.sqlalchemy import get_debug_queries
from . import main
from .forms import EditProfileForm, EditProfileAdminForm, QuestionForm,\
    AnswerForm, CommentForm, TopicForm
from .. import db
from ..models import Permission, Role, User, Question, Answer, Comment, Desc, Upvote, Fav, Topic
from ..decorators import admin_required, permission_required
from PIL import Image
from werkzeug import secure_filename

def redirect_url(default='main.index'):
    return request.args.get('next') or \
           request.referrer or \
           url_for(default)

@main.after_app_request
def after_request(response):
    for query in get_debug_queries():
        if query.duration >= current_app.config['FLASKY_SLOW_DB_QUERY_TIME']:
            current_app.logger.warning(
                'Slow query: %s\nParameters: %s\nDuration: %fs\nContext: %s\n'
                % (query.statement, query.parameters, query.duration,
                   query.context))
    return response


@main.route('/shutdown')
def server_shutdown():
    if not current_app.testing:
        abort(404)
    shutdown = request.environ.get('werkzeug.server.shutdown')
    if not shutdown:
        abort(500)
    shutdown()
    return 'Shutting down...'


@main.route('/', methods=['GET', 'POST'])
def index():
    form = QuestionForm()
    if current_user.can(Permission.WRITE_ARTICLES) and \
            form.validate_on_submit():
        q = Question(body=form.body.data,
                    author=current_user._get_current_object())
        db.session.add(q)
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    show_followed = False
    if current_user.is_authenticated:
        show_followed = bool(request.cookies.get('show_followed', ''))
    if show_followed:
        # query = current_user.followed_posts
        feed = current_user.feed
        # pagination = Pagination(page=page,total=len(feed),per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],record_name='feeds')
    else:
        query = Question.query
        pagination = query.order_by(Question.timestamp.desc()).paginate(
            page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
            error_out=False)
        feed = pagination.items
    return render_template('index.html', form=form, feeds=feed,
                           show_followed=show_followed)


@main.route('/user/<username>')
def user(username):
    user = User.query.filter_by(username=username).first_or_404()
    context = user.profile_context
    # page = request.args.get('page', 1, type=int)
    # pagination = user.questions.order_by(Question.timestamp.desc()).paginate(
    #     page, per_page=current_app.config['FLASKY_POSTS_PER_PAGE'],
    #     error_out=False)
    # posts = pagination.items
    return render_template('user.html', user=user, feeds=context)


@main.route('/edit-profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm()
    if form.validate_on_submit():
        current_user.name = form.name.data
        current_user.location = form.location.data
        current_user.about_me = form.about_me.data
        db.session.add(current_user)
        flash('Your profile has been updated.')
        return redirect(url_for('.user', username=current_user.username))
    form.name.data = current_user.name
    form.location.data = current_user.location
    form.about_me.data = current_user.about_me
    return render_template('edit_profile.html', form=form)


@main.route('/edit-profile/<int:id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_profile_admin(id):
    user = User.query.get_or_404(id)
    form = EditProfileAdminForm(user=user)
    if form.validate_on_submit():
        user.email = form.email.data
        user.username = form.username.data
        user.confirmed = form.confirmed.data
        user.role = Role.query.get(form.role.data)
        user.name = form.name.data
        user.location = form.location.data
        user.about_me = form.about_me.data
        db.session.add(user)
        flash('The profile has been updated.')
        return redirect(url_for('.user', username=user.username))
    form.email.data = user.email
    form.username.data = user.username
    form.confirmed.data = user.confirmed
    form.role.data = user.role_id
    form.name.data = user.name
    form.location.data = user.location
    form.about_me.data = user.about_me
    return render_template('edit_profile.html', form=form, user=user)


@main.route('/question/<int:id>', methods=['GET', 'POST'])
def question(id):
    q = Question.query.get_or_404(id)
    form = AnswerForm()
    if form.validate_on_submit():
        answer = Answer(body=form.body.data,
                          question=q,
                          author=current_user._get_current_object())
        db.session.add(answer)
        flash('Your answer has been published.')
        return redirect(url_for('.question', id=q.id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (q.answers.count() - 1) // \
            current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = q.answers.order_by(Answer.timestamp.asc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    answers = pagination.items
    return render_template('question.html', question=q, form=form,
                           answers=answers, pagination=pagination)

@main.route('/question/<int:id>/add', methods=['GET', 'POST'])
@login_required
def add_topic(id):
    q = Question.query.get_or_404(id)
    form = TopicForm()
    if form.validate_on_submit():
        q.add_topic(name=form.body.data)
        return redirect(url_for('.question',id=id))
    return render_template('question.html', question=q, form=form)

@main.route('/answer/<int:id>', methods=['GET', 'POST'])
def answer(id):
    a = Answer.query.get_or_404(id)
    form = CommentForm()
    if form.validate_on_submit():
        comment = Comment(body=form.body.data,
                            answer=a,
                            author=current_user._get_current_object())
        db.session.add(comment)
        flash('Your comment has been published')
        return redirect(url_for('.answer',id=id, page=-1))
    page = request.args.get('page', 1, type=int)
    if page == -1:
        page = (a.comments.count() - 1) // \
            current_app.config['FLASKY_COMMENTS_PER_PAGE'] + 1
    pagination = a.comments.order_by(Comment.timestamp.asc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('answer.html', answer=a, form=form,
                           comments=comments, pagination=pagination)



@main.route('/edit/q/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_question(id):
    q = Question.query.get_or_404(id)
    if current_user != q.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = QuestionForm()
    if form.validate_on_submit():
        # q.body = form.body.data
        # db.session.add(q)
        q.update_question(form.body.data)
        flash('The question has been updated.')
        return redirect(url_for('.question', id=q.id))
    form.body.data = q.body
    return render_template('edit_post.html', form=form)

@main.route('/edit/a/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_answer(id):
    a = Answer.query.get_or_404(id)
    if current_user != a.author and \
            not current_user.can(Permission.ADMINISTER):
        abort(403)
    form = AnswerForm()
    if form.validate_on_submit():
        a.body = form.body.data
        db.session.add(a)
        flash('The question has been updated.')
        return redirect(url_for('.answer', id=a.id))
    form.body.data = a.body
    return render_template('edit_post.html', form=form)


@main.route('/follow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if current_user.is_following(user):
        flash('You are already following this user.')
        return redirect(url_for('.user', username=username))
    current_user.follow(user)
    flash('You are now following %s.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/unfollow/<username>')
@login_required
@permission_required(Permission.FOLLOW)
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    if not current_user.is_following(user):
        flash('You are not following this user.')
        return redirect(url_for('.user', username=username))
    current_user.unfollow(user)
    flash('You are not following %s anymore.' % username)
    return redirect(url_for('.user', username=username))


@main.route('/followers/<username>')
def followers(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followers.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.follower, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followers of",
                           endpoint='.followers', pagination=pagination,
                           follows=follows)


@main.route('/followed-by/<username>')
def followed_by(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('Invalid user.')
        return redirect(url_for('.index'))
    page = request.args.get('page', 1, type=int)
    pagination = user.followed.paginate(
        page, per_page=current_app.config['FLASKY_FOLLOWERS_PER_PAGE'],
        error_out=False)
    follows = [{'user': item.followed, 'timestamp': item.timestamp}
               for item in pagination.items]
    return render_template('followers.html', user=user, title="Followed by",
                           endpoint='.followed_by', pagination=pagination,
                           follows=follows)


@main.route('/upvote/<int:ans_id>')
@login_required
def upvote(ans_id):
    answer = Answer.query.filter_by(id=ans_id).first()
    if answer is None:
        flash('Invalid Question.')
        return redirect(redirect_url())
    author = current_user._get_current_object()
    if current_user.has_upvoted(answer):
        flash('You has upvoted this answer')
        return redirect(redirect_url())
    current_user.up_answer(answer)
    # return redirect(url_for('.answer', id=ans_id))
    return redirect(redirect_url())

@main.route('/downvote/<int:ans_id>')
@login_required
def downvote(ans_id):
    answer = Answer.query.filter_by(id=ans_id).first()
    if answer is None:
        flash('Invalid answer.')
        return redirect(redirect_url())
    author = current_user._get_current_object()
    if current_user.has_downvoted(answer):
        flash('You has downvoted this answer')
        return redirect(redirect_url())
    current_user.down_answer(answer)
    return redirect(redirect_url())

@main.route('/notification/<int:id>')
@login_required
def notification(id):
    if current_user.id != id:
        flash('Permission denied')
        return redirect(redirect_url())
    n = current_user.notification
    # u = User.query.get(id)
    # n = u.notification
    return render_template('notification.html',infos=n)

@main.route('/fav')
@login_required
def favor():
    f = current_user.favor
    return render_template('fav.html',infos=f)

@main.route('/fav/<int:id>')
@login_required
def add_favor(id):
    author = current_user._get_current_object()
    answer = Answer.query.get(id)
    if answer is None:
        flash('Invalid answer.')
        return redirect(redirect_url())
    query = Fav.query.filter_by(answer=answer,author=author).first()
    if query is not None:
        flash('You has favored this answer.')
        return redirect(redirect_url())
    f = Fav(answer=answer,author=author)
    db.session.add(f)
    db.session.commit()
    return redirect(redirect_url())

@main.route('/unfav/<int:id>')
@login_required
def delete_favor(id):
    author = current_user._get_current_object()
    answer = Answer.query.get(id)
    if answer is None:
        flash('Invalid answer.')
        return redirect(redirect_url())
    query = Fav.query.filter_by(answer=answer,author=author).first()
    if query is None:
        return redirect(redirect_url())
    db.session.delete(query)
    db.session.commit()
    return redirect(redirect_url())

@main.route('/topic/<int:id>')
@login_required
def topic(id):
    topic = Topic.query.get_or_404(id)
    f = topic.feeds
    return render_template('topic.html', feeds=f)

@main.route('/all')
@login_required
def show_all():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '', max_age=30*24*60*60)
    return resp


@main.route('/followed')
@login_required
def show_followed():
    resp = make_response(redirect(url_for('.index')))
    resp.set_cookie('show_followed', '1', max_age=30*24*60*60)
    return resp


@main.route('/moderate')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate():
    page = request.args.get('page', 1, type=int)
    pagination = Comment.query.order_by(Comment.timestamp.desc()).paginate(
        page, per_page=current_app.config['FLASKY_COMMENTS_PER_PAGE'],
        error_out=False)
    comments = pagination.items
    return render_template('moderate.html', comments=comments,
                           pagination=pagination, page=page)


@main.route('/moderate/enable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_enable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = False
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))


@main.route('/moderate/disable/<int:id>')
@login_required
@permission_required(Permission.MODERATE_COMMENTS)
def moderate_disable(id):
    comment = Comment.query.get_or_404(id)
    comment.disabled = True
    db.session.add(comment)
    return redirect(url_for('.moderate',
                            page=request.args.get('page', 1, type=int)))

@main.route('/edit-avatar', methods=['GET', 'POST'])
@login_required
def change_avatar():
    if request.method == 'POST':
        file = request.files['file']
        size = (256, 256)
        im = Image.open(file)
        im.thumbnail(size)
        if file: #and allowed_file(file.filename):
            user = current_user._get_current_object()
            filename = user.avatar_hash + '.jpg'
            user.use_default_avatar = False
            db.session.add(user)
#            filename = secure_filename(file.filename)
            im.save(os.path.join('app','static', 'avatar', filename))
#            current_user.new_avatar_file = url_for('main.static', filename='%s/%s' % ('avatar', filename))
#            current_user.is_avatar_default = False
            flash(u'avatart changed')
            return redirect(url_for('.index'))
    return render_template('edit_avatar.html')
