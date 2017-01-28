<?php
namespace packages\whois;
class ru_handler {

    function parse($data_str, $query) {
        $items = array(
            'domain:' => 'domain.name',
            'registrar:' => 'domain.sponsor',
            'state:' => 'domain.status',
            'nserver:' => 'domain.nserver.',
            'source:' => 'domain.source',
            'created:' => 'domain.created',
            'paid-till:' => 'domain.expires',
            'type:' => 'owner.type',
            'org:' => 'owner.organization',
            'phone:' => 'owner.phone',
            'fax-no:' => 'owner.fax',
            'e-mail:' => 'owner.email'
        );

        $r = array();
        $r['regrinfo'] = generic_parser_b($data_str['rawdata'], $items, 'dmy');

        if (empty($r['regrinfo']['domain']['status']))
            $r['regrinfo']['registered'] = 'no';

        $r['regyinfo'] = array(
            'referrer' => 'http://www.ripn.net',
            'registrar' => 'RU-CENTER-REG-RIPN'
        );
        return $r;
    }

}
