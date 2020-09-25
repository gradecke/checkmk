#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019 tribe29 GmbH - License: GNU General Public License v2
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

# .1.3.6.1.2.1.1.1.0 Linux gateway1 2.6.18-92cp #1 SMP Tue Dec 4 21:44:22 IST 2012 i686
# .1.3.6.1.4.1.2620.1.1.25.3.0 19190

from typing import Dict

from .agent_based_api.v1 import check_levels, register, Service, SNMPTree
from .agent_based_api.v1.type_defs import CheckResult, DiscoveryResult, Parameters, SNMPStringTable
from .utils import checkpoint

checkpoint_connections_default_levels = {"pct": (80, 90)}

Section = Dict[str, int]


def parse_checkpoint_connections(string_table: SNMPStringTable) -> Section:
    print(string_table)
    current_raw_value = string_table[0][0][0]
    peak_raw_value = string_table[0][0][1]
    maximum_raw_value = string_table[0][0][2]
    return {
        "current": int(current_raw_value),
        "peak": int(peak_raw_value),
        "maximum": int(maximum_raw_value),
    }


register.snmp_section(
    name="checkpoint_connections",
    parse_function=parse_checkpoint_connections,
    detect=checkpoint.DETECT,
    trees=[
        SNMPTree(
            base=".1.3.6.1.4.1.2620.1.1.25",
            oids=[
                '3',  # CHECKPOINT-MIB - fwNumConn - current connections
                '4',  # CHECKPOINT-MIB - fwPeakNumConn - peak number of connections
                '10',  # CHECKPOINT-MIB - fwConnTableLimit - connection table limit
            ])
    ],
)


def discover_checkpoint_connections(section: Section) -> DiscoveryResult:
    yield Service()


def check_checkpoint_connections(
    params: Parameters,
    section: Section,
) -> CheckResult:
    current = section['current']
    peak = section['peak']
    maximum = section['maximum']
    #infotext = "%d current, %d peak, %d maximum" % (current, peak, maximum)

    if type(params) is dict and "pct" in params:
        warn_pct, crit_pct = params["pct"]
        warn = maximum * warn_pct / 100
        crit = maximum * crit_pct / 100
    else:
        # up until cmk 1.6 this check only supported user set absolute values
        warn, crit = params

    yield from check_levels(value=current,
                            levels_upper=(warn, crit),
                            metric_name="connections",
                            label=(f"Current connections: {current}, Peak: {peak}, "
                                   f"Connection table limit: {maximum}" % section,))


register.check_plugin(name="checkpoint_connections",
                      service_name="Connections",
                      discovery_function=discover_checkpoint_connections,
                      check_function=check_checkpoint_connections,
                      check_default_parameters=checkpoint_connections_default_levels,
                      check_ruleset_name="checkpoint_connections")
