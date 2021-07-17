"""Initial migration.

Revision ID: 9c349bdbae17
Revises: 
Create Date: 2021-07-01 00:46:41.099762

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9c349bdbae17'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('ADMIN',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('registration_date', sa.DateTime(), nullable=False),
    sa.Column('password', sa.String(length=60), server_default='0', nullable=False),
    sa.Column('name', sa.String(length=100), nullable=True),
    sa.Column('email', sa.String(length=32), nullable=True),
    sa.Column('email_verified', sa.Integer(), server_default='0', nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('PICKUP_IMPAIRED',
    sa.Column('openid', sa.String(length=64), nullable=False),
    sa.Column('activity_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=32), nullable=True),
    sa.Column('id_no', sa.String(length=18), nullable=True),
    sa.Column('impaired_no', sa.String(length=20), nullable=True),
    sa.Column('pickup_addr', sa.String(length=256), nullable=True),
    sa.Column('emergency_contact', sa.String(length=32), nullable=True),
    sa.Column('pickup_method', sa.String(length=32), nullable=True),
    sa.Column('pickup_volunteer_openid', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('openid', 'activity_id')
    )
    op.create_table('PICKUP_VOLUNTEER',
    sa.Column('openid', sa.String(length=64), nullable=False),
    sa.Column('activity_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=32), nullable=True),
    sa.Column('id_no', sa.String(length=18), nullable=True),
    sa.Column('pickup_addr', sa.String(length=512), nullable=True),
    sa.Column('provide_service', sa.String(length=32), nullable=True),
    sa.PrimaryKeyConstraint('openid', 'activity_id')
    )
    op.create_table('USER',
    sa.Column('openid', sa.String(length=28), nullable=False),
    sa.Column('registration_date', sa.DateTime(), nullable=False),
    sa.Column('role', sa.Integer(), server_default='0', nullable=False),
    sa.Column('name', sa.String(length=100), nullable=True),
    sa.Column('real_name', sa.String(length=100), nullable=True),
    sa.Column('id_type', sa.String(length=100), nullable=True),
    sa.Column('idcard', sa.String(length=18), nullable=True),
    sa.Column('idcard_verified', sa.Integer(), server_default='0', nullable=True),
    sa.Column('disabled_id', sa.String(length=60), nullable=True),
    sa.Column('disabled_id_verified', sa.Integer(), server_default='0', nullable=True),
    sa.Column('phone', sa.String(length=16), nullable=False),
    sa.Column('phone_verified', sa.Integer(), server_default='0', nullable=False),
    sa.Column('email', sa.String(length=32), nullable=True),
    sa.Column('email_verified', sa.Integer(), server_default='0', nullable=True),
    sa.Column('contact', sa.String(length=16), nullable=True),
    sa.Column('gender', sa.String(length=1), server_default='无', nullable=False),
    sa.Column('birth', sa.DateTime(), nullable=False),
    sa.Column('address', sa.String(length=80), server_default='无', nullable=True),
    sa.Column('emergent_contact', sa.String(length=8), nullable=True),
    sa.Column('emergent_contact_phone', sa.String(length=16), nullable=True),
    sa.Column('activities_joined', sa.Integer(), server_default='0', nullable=False),
    sa.Column('activities_absence', sa.Integer(), server_default='0', nullable=False),
    sa.Column('remark', sa.String(length=255), server_default='无', nullable=True),
    sa.Column('audit_status', sa.Integer(), server_default='0', nullable=False),
    sa.Column('push_status', sa.Integer(), server_default='0', nullable=False),
    sa.Column('recipient_name', sa.String(length=100), nullable=True),
    sa.Column('recipient_address', sa.String(length=80), nullable=True),
    sa.Column('recipient_phone', sa.String(length=16), nullable=True),
    sa.PrimaryKeyConstraint('openid'),
    sa.UniqueConstraint('disabled_id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('idcard'),
    sa.UniqueConstraint('phone')
    )
    op.create_table('ACTIVITY',
    sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),
    sa.Column('title', sa.String(length=60), nullable=False),
    sa.Column('start_time', sa.DateTime(), nullable=False),
    sa.Column('location', sa.String(length=100), nullable=False),
    sa.Column('location_latitude', sa.DECIMAL(precision=9, scale=6), nullable=True),
    sa.Column('location_longitude', sa.DECIMAL(precision=9, scale=6), nullable=True),
    sa.Column('end_time', sa.DateTime(), nullable=True),
    sa.Column('content', sa.String(length=4000), nullable=False),
    sa.Column('notice', sa.String(length=4000), nullable=True),
    sa.Column('others', sa.String(length=120), server_default='无', nullable=False),
    sa.Column('admin_raiser', sa.Integer(), nullable=True),
    sa.Column('user_raiser', sa.String(length=28), nullable=True),
    sa.Column('approver', sa.Integer(), nullable=True),
    sa.Column('assignee', sa.String(length=28), nullable=True),
    sa.Column('published', sa.Integer(), server_default='0', nullable=False),
    sa.Column('tag_ids', sa.String(length=120), nullable=True),
    sa.Column('volunteer_capacity', sa.Integer(), server_default='0', nullable=True),
    sa.Column('vision_impaired_capacity', sa.Integer(), server_default='0', nullable=True),
    sa.Column('volunteer_job_title', sa.String(length=500), nullable=True),
    sa.Column('volunteer_job_content', sa.String(length=100), nullable=True),
    sa.Column('activity_fee', sa.Integer(), server_default='0', nullable=True),
    sa.Column('sign_in_radius', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['admin_raiser'], ['ADMIN.id'], ),
    sa.ForeignKeyConstraint(['approver'], ['ADMIN.id'], ),
    sa.ForeignKeyConstraint(['assignee'], ['USER.openid'], ),
    sa.ForeignKeyConstraint(['user_raiser'], ['USER.openid'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('ACTIVITY_PARTICIPANT',
    sa.Column('activity_id', sa.BigInteger(), nullable=False),
    sa.Column('participant_openid', sa.String(length=28), nullable=False),
    sa.Column('interested', sa.Integer(), server_default='0', nullable=True),
    sa.Column('share', sa.Integer(), server_default='0', nullable=True),
    sa.Column('thumbs_up', sa.Integer(), server_default='0', nullable=True),
    sa.Column('certificated', sa.Integer(), nullable=True),
    sa.Column('certiticate_date', sa.DateTime(), nullable=True),
    sa.Column('paper_certificate', sa.Integer(), nullable=True),
    sa.Column('signup_time', sa.DateTime(), nullable=True),
    sa.Column('signup_latitude', sa.DECIMAL(precision=9, scale=6), nullable=True),
    sa.Column('signup_longitude', sa.DECIMAL(precision=9, scale=6), nullable=True),
    sa.Column('signoff_time', sa.DateTime(), nullable=True),
    sa.Column('signoff_latitude', sa.DECIMAL(precision=9, scale=6), nullable=True),
    sa.Column('signoff_longitude', sa.DECIMAL(precision=9, scale=6), nullable=True),
    sa.ForeignKeyConstraint(['activity_id'], ['ACTIVITY.id'], ),
    sa.ForeignKeyConstraint(['participant_openid'], ['USER.openid'], ),
    sa.PrimaryKeyConstraint('activity_id', 'participant_openid')
    )
    op.create_table('PICKUP_PAIR',
    sa.Column('activity_id', sa.BigInteger(), nullable=True),
    sa.Column('offer', sa.String(length=28), nullable=False),
    sa.Column('need', sa.String(length=28), nullable=False),
    sa.Column('time', sa.DateTime(), nullable=False),
    sa.Column('location', sa.String(length=100), nullable=False),
    sa.ForeignKeyConstraint(['activity_id'], ['ACTIVITY.id'], ),
    sa.ForeignKeyConstraint(['need'], ['USER.openid'], ),
    sa.ForeignKeyConstraint(['offer'], ['USER.openid'], ),
    sa.PrimaryKeyConstraint('offer', 'need')
    )
    op.create_table('REGISTERED_ACTIVITY',
    sa.Column('user_openid', sa.String(length=28), nullable=False),
    sa.Column('activity_id', sa.BigInteger(), nullable=False),
    sa.Column('phone', sa.String(length=16), nullable=False),
    sa.Column('address', sa.String(length=80), nullable=False),
    sa.Column('needpickup', sa.Integer(), server_default='0', nullable=False),
    sa.Column('topickup', sa.Integer(), server_default='0', nullable=False),
    sa.Column('accepted', sa.Integer(), server_default='-1', nullable=False),
    sa.ForeignKeyConstraint(['activity_id'], ['ACTIVITY.id'], ),
    sa.ForeignKeyConstraint(['user_openid'], ['USER.openid'], ),
    sa.PrimaryKeyConstraint('user_openid', 'activity_id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('REGISTERED_ACTIVITY')
    op.drop_table('PICKUP_PAIR')
    op.drop_table('ACTIVITY_PARTICIPANT')
    op.drop_table('ACTIVITY')
    op.drop_table('USER')
    op.drop_table('PICKUP_VOLUNTEER')
    op.drop_table('PICKUP_IMPAIRED')
    op.drop_table('ADMIN')
    # ### end Alembic commands ###
