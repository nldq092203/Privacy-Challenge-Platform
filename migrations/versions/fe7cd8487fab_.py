"""empty message

Revision ID: fe7cd8487fab
Revises: 
Create Date: 2025-04-06 18:07:09.514115

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'fe7cd8487fab'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('aggregations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=32), nullable=False),
    sa.Column('is_selected', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('aggregations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_aggregations_is_selected'), ['is_selected'], unique=False)
        batch_op.create_index(batch_op.f('ix_aggregations_name'), ['name'], unique=True)

    op.create_table('blacklisted_tokens',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('jti', sa.String(length=36), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('jti')
    )
    op.create_table('group_users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('invite_keys',
    sa.Column('key', sa.String(length=6), nullable=False),
    sa.Column('created', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )
    op.create_table('metrics',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=32), nullable=False),
    sa.Column('is_selected', sa.Boolean(), nullable=False),
    sa.Column('parameters', sa.String(length=32), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('metrics', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_metrics_is_selected'), ['is_selected'], unique=False)
        batch_op.create_index(batch_op.f('ix_metrics_name'), ['name'], unique=True)

    op.create_table('roles',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('default', sa.Boolean(), nullable=False),
    sa.Column('permissions', sa.Integer(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    with op.batch_alter_table('roles', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_roles_default'), ['default'], unique=False)

    op.create_table('anonymisations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('footprint_file', sa.String(length=255), nullable=True),
    sa.Column('shuffled_file', sa.String(length=255), nullable=True),
    sa.Column('original_file', sa.String(length=255), nullable=False),
    sa.Column('file_link', sa.String(length=255), nullable=False),
    sa.Column('naive_attack', sa.Float(), nullable=False),
    sa.Column('utility', sa.Float(), nullable=False),
    sa.Column('status', sa.String(length=255), nullable=False),
    sa.Column('name', sa.String(length=64), nullable=False),
    sa.Column('is_published', sa.Boolean(), nullable=False),
    sa.Column('group_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['group_id'], ['group_users.id'], name='fk_anonym_group', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('file_link'),
    sa.UniqueConstraint('footprint_file'),
    sa.UniqueConstraint('shuffled_file')
    )
    with op.batch_alter_table('anonymisations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_anonymisations_is_published'), ['is_published'], unique=False)
        batch_op.create_index(batch_op.f('ix_anonymisations_name'), ['name'], unique=False)

    op.create_table('users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('_password', sa.String(length=256), nullable=False),
    sa.Column('email', sa.String(length=64), nullable=False),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('(false)'), nullable=False),
    sa.Column('group_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['group_id'], ['group_users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('attacks',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('score', sa.Float(), nullable=False),
    sa.Column('file', sa.String(length=255), nullable=False),
    sa.Column('anonym_id', sa.Integer(), nullable=False),
    sa.Column('group_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['anonym_id'], ['anonymisations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['group_id'], ['group_users.id'], name='fk_attack_group', ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('file')
    )
    op.create_table('roles_users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('role_id', sa.Integer(), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('roles_users')
    op.drop_table('attacks')
    op.drop_table('users')
    with op.batch_alter_table('anonymisations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_anonymisations_name'))
        batch_op.drop_index(batch_op.f('ix_anonymisations_is_published'))

    op.drop_table('anonymisations')
    with op.batch_alter_table('roles', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_roles_default'))

    op.drop_table('roles')
    with op.batch_alter_table('metrics', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_metrics_name'))
        batch_op.drop_index(batch_op.f('ix_metrics_is_selected'))

    op.drop_table('metrics')
    op.drop_table('invite_keys')
    op.drop_table('group_users')
    op.drop_table('blacklisted_tokens')
    with op.batch_alter_table('aggregations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_aggregations_name'))
        batch_op.drop_index(batch_op.f('ix_aggregations_is_selected'))

    op.drop_table('aggregations')
    # ### end Alembic commands ###
