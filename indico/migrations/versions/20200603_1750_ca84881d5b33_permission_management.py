"""permission management

Revision ID: ca84881d5b33
Revises: 532f0ea25bb1
Create Date: 2020-06-03 17:50:48.783612
"""

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision = 'ca84881d5b33'
down_revision = '532f0ea25bb1'
branch_labels = None
depends_on = None


def upgrade():
    op.execute('create schema permissions')
    op.create_table(
        'roles',
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_roles')),
        schema='permissions'
    )
    op.create_table(
        'permissions',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['role_id'], [u'permissions.roles.id'], name=op.f('fk_permissions_role_id_roles')),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_permissions')),
        schema='permissions'
    )
    op.create_table(
        'user_roles',
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('group_id', sa.Integer(), nullable=True),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.Column('main_table', sa.String(), nullable=False),
        sa.Column('side_table', sa.String(), nullable=True),
        sa.Column('main_pk', sa.Integer(), nullable=False),
        sa.Column('side_pk', sa.Integer(), nullable=True),
        sa.CheckConstraint(u'((user_id is null and role_id is not null) or (user_id is not null and role_id is null))',
                           name=op.f('ck_user_roles_user_or_role')),
        sa.ForeignKeyConstraint(['group_id'], [u'users.groups.id'], name=op.f('fk_user_roles_group_id_groups')),
        sa.ForeignKeyConstraint(['role_id'], [u'permissions.roles.id'], name=op.f('fk_user_roles_role_id_roles')),
        sa.ForeignKeyConstraint(['user_id'], [u'users.users.id'], name=op.f('fk_user_roles_user_id_users')),
        sa.UniqueConstraint('group_id', 'user_id', 'role_id', 'main_table', 'main_pk', 'side_table', 'side_pk', name=op.f('uq_user_roles_group_id_user_id_role_id_main_table_main_pk_side_table_side_pk')),
        schema='permissions'
    )
    op.create_index(op.f('ix_user_roles_group_id'), 'user_roles', ['group_id'], unique=False, schema='permissions')
    op.create_index(op.f('ix_user_roles_main_pk'), 'user_roles', ['main_pk'], unique=False, schema='permissions')
    op.create_index(op.f('ix_user_roles_main_table'), 'user_roles', ['main_table'], unique=False, schema='permissions')
    op.create_index(op.f('ix_user_roles_role_id'), 'user_roles', ['role_id'], unique=False, schema='permissions')
    op.create_index(op.f('ix_user_roles_side_pk'), 'user_roles', ['side_pk'], unique=False, schema='permissions')
    op.create_index(op.f('ix_user_roles_side_table'), 'user_roles', ['side_table'], unique=False, schema='permissions')
    op.create_index(op.f('ix_user_roles_user_id'), 'user_roles', ['user_id'], unique=False, schema='permissions')


def downgrade():
    op.drop_index(op.f('ix_user_roles_user_id'), table_name='user_roles', schema='permissions')
    op.drop_index(op.f('ix_user_roles_side_table'), table_name='user_roles', schema='permissions')
    op.drop_index(op.f('ix_user_roles_side_pk'), table_name='user_roles', schema='permissions')
    op.drop_index(op.f('ix_user_roles_role_id'), table_name='user_roles', schema='permissions')
    op.drop_index(op.f('ix_user_roles_main_table'), table_name='user_roles', schema='permissions')
    op.drop_index(op.f('ix_user_roles_main_pk'), table_name='user_roles', schema='permissions')
    op.drop_index(op.f('ix_user_roles_group_id'), table_name='user_roles', schema='permissions')
    op.drop_table('user_roles', schema='permissions')
    op.drop_table('permissions', schema='permissions')
    op.drop_table('roles', schema='permissions')
    op.execute('drop schema permissions')
