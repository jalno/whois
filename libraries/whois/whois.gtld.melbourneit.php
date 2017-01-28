<?php
namespace packages\whois;
class melbourneit_handler {

    function parse($data_str, $query) {
        $items = array(
            'Domain Name..........' => 'domain.name',
            'Registration Date....' => 'domain.created',
            'Expiry Date..........' => 'domain.expires',
            'Organisation Name....' => 'owner.name',
            'Organisation Address.' => 'owner.address.',
            'Admin Name...........' => 'admin.name',
            'Admin Address........' => 'admin.address.',
            'Admin Email..........' => 'admin.email',
            'Admin Phone..........' => 'admin.phone',
            'Admin Fax............' => 'admin.fax',
            'Tech Name............' => 'tech.name',
            'Tech Address.........' => 'tech.address.',
            'Tech Email...........' => 'tech.email',
            'Tech Phone...........' => 'tech.phone',
            'Tech Fax.............' => 'tech.fax',
            'Name Server..........' => 'domain.nserver.'
        );

        return generic_parser_b($data_str, $items, 'ymd');
    }

}
