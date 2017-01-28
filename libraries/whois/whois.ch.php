<?php
namespace packages\whois;
class ch_handler {

    function parse($data_str, $query) {

        $items = array(
            'owner' => 'Holder of domain name:',
            'domain.name' => 'Domain name:',
            'domain.created' => 'Date of last registration:',
            'domain.changed' => 'Date of last modification:',
            'tech' => 'Technical contact:',
            'domain.nserver' => 'Name servers:',
            'domain.dnssec' => 'DNSSEC:'
        );

        $trans = array(
            'contractual language:' => 'language'
        );

        $r = array();
        $r['regrinfo'] = get_blocks($data_str['rawdata'], $items);

        if (!empty($r['regrinfo']['domain']['name'])) {
            $r['regrinfo'] = get_contacts($r['regrinfo'], $trans);

            $r['regrinfo']['domain']['name'] = $r['regrinfo']['domain']['name'][0];

            if (isset($r['regrinfo']['domain']['changed'][0]))
                $r['regrinfo']['domain']['changed'] = get_date($r['regrinfo']['domain']['changed'][0], 'dmy');

            if (isset($r['regrinfo']['domain']['created'][0]))
                $r['regrinfo']['domain']['created'] = get_date($r['regrinfo']['domain']['created'][0], 'dmy');

            $r['regrinfo']['registered'] = 'yes';
        } else {
            $r = '';
            $r['regrinfo']['registered'] = 'no';
        }

        $r['regyinfo'] = array(
            'referrer' => 'http://www.nic.ch',
            'registrar' => 'SWITCH Domain Name Registration'
        );
        return $r;
    }

}
