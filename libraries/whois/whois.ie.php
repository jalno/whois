<?php
namespace packages\whois;
class ie_handler {

    function parse($data_str, $query) {
        $translate = array(
            'nic-hdl' => 'handle',
            'person' => 'name',
            'renewal' => 'expires'
        );

        $contacts = array(
            'admin-c' => 'admin',
            'tech-c' => 'tech',
        );

        $reg = generic_parser_a($data_str['rawdata'], $translate, $contacts, 'domain', 'Ymd');

        if (isset($reg['domain']['descr'])) {
            $reg['owner']['organization'] = $reg['domain']['descr'][0];
            unset($reg['domain']['descr']);
        }

        $r = array();
        $r['regrinfo'] = $reg;
        $r['regyinfo'] = array(
            'referrer' => 'http://www.domainregistry.ie',
            'registrar' => 'IE Domain Registry'
        );
        return $r;
    }

}
