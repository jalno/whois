<?php
namespace packages\whois;
class lt_handler {

    function parse($data_str, $query) {
        $translate = array(
            'contact nic-hdl:' => 'handle',
            'contact name:' => 'name'
        );

        $items = array(
            'admin' => 'Contact type:      Admin',
            'tech' => 'Contact type:      Tech',
            'zone' => 'Contact type:      Zone',
            'owner.name' => 'Registrar:',
            'owner.email' => 'Registrar email:',
            'domain.status' => 'Status:',
            'domain.created' => 'Registered:',
            'domain.changed' => 'Last updated:',
            'domain.nserver.' => 'NS:',
            '' => '%'
        );

        $r = array();
        $r['regrinfo'] = easy_parser($data_str['rawdata'], $items, 'ymd', $translate);

        $r['regyinfo'] = array(
            'referrer' => 'http://www.domreg.lt',
            'registrar' => 'DOMREG.LT'
        );
        return $r;
    }

}
