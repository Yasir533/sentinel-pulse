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
    # 1. Add user columns if they do not exist
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('last_seen_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('failed_login_attempts', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('lockout_until', sa.DateTime(), nullable=True))

    # 2. Create ai_decisions table
    op.create_table('ai_decisions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('input_type', sa.String(length=50), nullable=False),
        sa.Column('input_value', sa.Text(), nullable=False),
        sa.Column('engine_type', sa.String(length=50), nullable=False, server_default='Hybrid-Rule-ML'),
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
    with op.batch_alter_table('ai_decisions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ai_decisions_created_at'))
        batch_op.drop_index(batch_op.f('ix_ai_decisions_input_type'))
        batch_op.drop_index(batch_op.f('ix_ai_decisions_user_id'))
    op.drop_table('ai_decisions')

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('lockout_until')
        batch_op.drop_column('failed_login_attempts')
        batch_op.drop_column('last_seen_at')
