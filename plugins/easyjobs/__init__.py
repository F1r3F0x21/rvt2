#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) INCIDE Digital Data S.L.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

""" Make writing and using modules easier """

from inspect import signature, _empty, getdoc
from base.job import BaseModule
from base.config import default_config


def simplejob(params_help=dict()):
    def inner_decorator(func):
        """ A decorator to simplify the module development.

        Using this decorator, a RVT2 module is a function that:

        - Only accepts one optional positional parameter named `ctx`. This if the BaseModule and you can access
        `from_module` from here, for example
        - Get any number of named parameters. These parameters are the configuration of of the Module. They
        MUST have a default value and they COULD be annotated as int, bool or str, and the parameter will
        be converted accordingly. If they are not annotated, str is assumed.
        - Return an iterator, or None

        You can also call directly these functions by passing the config object.
        Check the examples below.
        """
        def wrapper(decorated_func):
            class InnerModuleClass(BaseModule):
                """ A dummy base module, helper to a simplejob """
                def run(self, path=None):
                    sig = signature(decorated_func)
                    if 'path' in sig.parameters:
                        return self.__call__(path=path)
                    return self.__call__()

                def __call__(self, *args, **kwargs):
                    sig = signature(decorated_func)
                    options = self.options()
                    # check all parameters of the function
                    for param in sig.parameters:
                        # get the annotation. Assumes it work as a converter
                        # from str to the right type. int, str and bool work OK.
                        param_type = sig.parameters[param].annotation
                        if param_type is _empty:
                            param_type = str
                        # if ctx is a param, pass self
                        if param == 'ctx':
                            kwargs[param] = self
                        # else, convert the parameter using the annotation as a function
                        elif param in options:
                            kwargs[param] = param_type(self.myconfig(param))
                    # finally, call to the decorated function
                    # return an empty decorator if the function returned None
                    retiter = decorated_func(**kwargs)
                    if retiter is None:
                        yield from ()
                    else:
                        yield from retiter
            return InnerModuleClass
        _register_job(func, params_help)
        return wrapper(func)
    return inner_decorator


def _register_job(func, params_help=dict()):
    """ Registers a job in a the default configuration

    Parameters:
        params_help (dict): a dictionary "name of the parameter" to "short help"
        func: the main function. Parameters are default_params, ctx is ignored.
    """
    # description
    desc = getdoc(func)
    if desc is None:
        desc = ''
    default_config.set(f'{func.__module__}.{func.__name__}', 'description', desc)
    # params help
    default_config.set(f'{func.__module__}.{func.__name__}', 'params_help', str(params_help))
    sig = signature(func)
    default_params = {}
    for param in sig.parameters:
        if param == 'ctx':
            continue
        default_params[param] = str(sig.parameters[param].default)
    default_config.set(f'{func.__module__}.{func.__name__}', 'default_params', str(default_params))
    default_config.set(f'{func.__module__}.{func.__name__}', 'help_section', func.__module__)


@simplejob(params_help=dict(
    count='Number of times the message must be returned',
    name='The name of the user'
))
def test(ctx: BaseModule, name: str = 'Alice', count: int = 0):
    """ A test for a simplejob.

    It will show "Hello NAME" a number of times, using counter() to show
    how simple jobs can call each other.
    """
    for i in counter()(to=count):
        yield dict(greetings=f'Hello {name} count+1={count+1} from_module={ctx.from_module}')


@simplejob()
def counter(to: int = 10):
    """ A test for a simplejob: return numbers from 0 to optional parameter to """
    return range(0, to)
