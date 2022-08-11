from functools import wraps

from click import option, echo

from flask import Blueprint
from common import sessionmaker
from ..base import Moderator, Permission, ModPerm, permission_index

CLI_PAGE_SIZE: int = 20

mub_cli_blueprint = Blueprint("mub", __name__)


def permission_cli_command():
    def permission_cli_command_wrapper(function):
        @mub_cli_blueprint.cli.command(function.__name__.replace("_", "-"))
        @wraps(function)
        @sessionmaker.with_begin
        def permission_cli_command_inner(*args, **kwargs):
            if not permission_index.initialized:
                return echo("FATAL: Permission index has not been initialized")
            return function(*args, **kwargs)

        return permission_cli_command_inner

    return permission_cli_command_wrapper


@permission_cli_command()
def list_permissions(session):
    permissions = Permission.get_all(session)
    if len(permissions) == 0:
        return echo("<empty>")

    for permission in permissions:
        echo(f"{permission.id:4}: {permission.name}")


@permission_cli_command()
@option("-u", "--username", prompt=True)
@option("-p", "--password", prompt=True, hide_input=True, confirmation_prompt=True)
def create_moderator(session, username: str, password: str):
    if Moderator.find_by_name(session, username) is not None:
        echo("ERROR: User with this name already exists")

    Moderator.register(session, username, password)


@permission_cli_command()
@option("-u", "--username", prompt=True)
@option("-p", "--password", prompt=True, hide_input=True, confirmation_prompt=True)
def create_super(session, username: str, password: str):
    if Moderator.find_by_name(session, username) is not None:
        echo("ERROR: Moderator with this name already exists\n"
             f"Hint: to upgrade a moderator to SUPER use:\n"
             f"activate-super -u {username}")

    moderator = Moderator.register(session, username, password)
    moderator.super = True


@permission_cli_command()
@option("-u", "--username", prompt=True)
def activate_super(session, username: str):
    moderator: Moderator = Moderator.find_by_name(session, username)
    if moderator is None:
        return echo("ERROR: Moderator does not exist")
    moderator.super = True


@permission_cli_command()
@option("-u", "--username", prompt=True)
def deactivate_super(session, username: str):
    moderator: Moderator = Moderator.find_by_name(session, username)
    if moderator is None:
        return echo("ERROR: Moderator does not exist")
    moderator.super = False


@permission_cli_command()
@option("-u", "--username", prompt=True)
def remove_moderator(session, username: str):
    moderator: Moderator = Moderator.find_by_name(session, username)
    if moderator is None:
        return echo("ERROR: Moderator does not exist")
    moderator.delete(session)


@permission_cli_command()
@option("-p", "--page", prompt=True, type=int)
def list_moderators(session, page: int):
    moderators = Moderator.search(session, page * CLI_PAGE_SIZE, CLI_PAGE_SIZE)

    if len(moderators) == 0:
        return echo("<empty>")

    for moderator in moderators:
        echo(f"{moderator.id:4}: {moderator.username}" + (" SUPER" if moderator.super else ""))


@permission_cli_command()
@option("-u", "--username", prompt=True)
@option("-p", "--permission", prompt=True)
def add_permission(session, username: str, permission: str):
    perm = Permission.find_by_name(session, permission)
    moderator = Moderator.find_by_name(session, username)
    if perm is None:
        return echo("ERROR: Permission does not exist")
    if moderator is None:
        return echo("ERROR: Moderator does not exist")
    if moderator.super or ModPerm.create_unique(session, moderator.id, perm.id) is None:
        echo("WARNING: Permission already granted")


@permission_cli_command()
@option("-u", "--username", prompt=True)
@option("-p", "--permission", prompt=True)
def remove_permission(session, username: str, permission: str):
    perm = Permission.find_by_name(session, permission)
    moderator = Moderator.find_by_name(session, username)
    if perm is None:
        return echo("ERROR: Permission does not exist")
    if moderator is None:
        return echo("ERROR: Moderator does not exist")
    if moderator.super:
        echo("ERROR: Moderator is SUPER")
    if not ModPerm.delete_by_ids(session, moderator.id, perm.id):
        echo("WARNING: Permission is not granted")


@permission_cli_command()
@option("-u", "--username", prompt=True)
def list_mod_perms(session, username: str):
    moderator = Moderator.find_by_name(session, username)
    if moderator is None:
        return echo("ERROR: Moderator does not exist")

    permissions = moderator.get_permissions(session)

    if len(permissions) == 0:
        return echo("<empty>")

    for permission in permissions:
        echo(f"{permission.id:4}: {permission.name}")
