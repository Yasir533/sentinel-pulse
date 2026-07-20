"""Add AI Decision and User Security Columns

Revision ID: c1f58291a100
Revises: ed16ab843384
Create Date: 2026-07-20 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c1f58291a100'
down_revision = 'ed16ab843384'
branch_labels = None
depends_on = None


def upgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # 1. Safely add user columns if they do not already exist
    existing_user_columns = [col['name'] for col in inspector.get_columns('users')]
    with op.batch_alter_table('users', schema=None) as batch_op:
        if 'last_seen_at' not in existing_user_columns:
            batch_op.add_column(sa.Column('last_seen_at', sa.DateTime(), nullable=True))
        if 'failed_login_attempts' not in existing_user_columns:
            batch_op.add_column(sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
        if 'lockout_until' not in existing_user_columns:
            batch_op.add_column(sa.Column('lockout_until', sa.DateTime(), nullable=True))

    # 2. Safely create ai_decisions table if it does not already exist
    existing_tables = inspector.get_table_names()
    if 'ai_decisions' not in existing_tables:
        op.create_table('ai_decisions',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=True),
            sa.Column('input_type', sa.String(length=50), nullable=False),
            sa.Column('input_value', sa.Text(), nullable=False),
            sa.Column('engine_type', sa.String(length=50), nullable=False, server_default='Hybrid Rule & Threat Intel Engine'),
            sa.Column('risk_score', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('confidence', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('severity', sa.String(length=20), nullable=False, server_default='Medium'),
            sa.Column('verdict', sa.String(length=20), nullable=False, server_default='ALLOW'),
            sa.Column('reasoning_summary', sa.Text(), nullable=True),
            sa.Column('mitre_tactic', sa.String(length=100), nullable=True),
            sa.Column('mitre_technique', sa.String(length=100), nullable=True),
            sa.Column('sources_consulted', sa.String(length=255), nullable=True),
            sa.Column('recommended_action', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
            sa.PrimaryKeyConstraint('id')
        )
        with op.batch_alter_table('ai_decisions', schema=None) as batch_op:
            batch_op.create_index(batch_op.f('ix_ai_decisions_user_id'), ['user_id'], unique=False)
            batch_op.create_index(batch_op.f('ix_ai_decisions_input_type'), ['input_type'], unique=False)
            batch_op.create_index(batch_op.f('ix_ai_decisions_created_at'), ['created_at'], unique=False)


def downgrade():
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = inspector.get_table_names()

    if 'ai_decisions' in existing_tables:
        with op.batch_alter_table('ai_decisions', schema=None) as batch_op:
            batch_op.drop_index(batch_op.f('ix_ai_decisions_created_at'))
            batch_op.drop_index(batch_op.f('ix_ai_decisions_input_type'))
            batch_op.drop_index(batch_op.f('ix_ai_decisions_user_id'))
        op.drop_table('ai_decisions')

    existing_user_columns = [col['name'] for col in inspector.get_columns('users')]
    with op.batch_alter_table('users', schema=None) as batch_op:
        if 'lockout_until' in existing_user_columns:
            batch_op.drop_column('lockout_until')
        if 'failed_login_attempts' in existing_user_columns:
            batch_op.drop_column('failed_login_attempts')
        if 'last_seen_at' in existing_user_columns:
            batch_op.drop_column('last_seen_at')
