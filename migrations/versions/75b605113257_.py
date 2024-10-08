"""empty message

Revision ID: 75b605113257
Revises: 0df6416abad6
Create Date: 2024-07-31 15:16:17.377059
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '75b605113257'
down_revision = '0df6416abad6'
branch_labels = None
depends_on = None

def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('problem', schema=None) as batch_op:
        batch_op.create_foreign_key(
            'fk_problem_user',  # Name of the foreign key constraint
            'user',  # Target table
            ['assigned_to'],  # Local columns
            ['id']  # Remote columns
        )
    # ### end Alembic commands ###

def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('problem', schema=None) as batch_op:
        batch_op.drop_constraint('fk_problem_user', type_='foreignkey')
    # ### end Alembic commands ###
