<?php
namespace packages\whois;
class de_handler {

    function parse($data_str, $query) {
        $items = array(
            'domain.name' => 'Domain:',
            'domain.nserver.' => 'Nserver:',
            'domain.nserver.#' => 'Nsentry:',
            'domain.status' => 'Status:',
            'domain.changed' => 'Changed:',
            'domain.desc.' => 'Descr:',
            'owner' => '[Holder]',
            'admin' => '[Admin-C]',
            'tech' => '[Tech-C]',
            'zone' => '[Zone-C]'
        );

        $extra = array(
            'city:' => 'address.city',
            'postalcode:' => 'address.pcode',
            'countrycode:' => 'address.country',
            'remarks:' => '',
            'sip:' => 'sip',
            'type:' => ''
        );

        $r = array();

        $r['regrinfo'] = easy_parser($data_str['rawdata'], $items, 'ymd', $extra);

        $r['regyinfo'] = array(
            'registrar' => 'DENIC eG',
            'referrer' => 'http://www.denic.de/'
        );

        if (!isset($r['regrinfo']['domain']['status']) || $r['regrinfo']['domain']['status'] == "free") {
            $r['regrinfo']['registered'] = 'no';
        } else {
            $r['regrinfo']['domain']['changed'] = substr($r['regrinfo']['domain']['changed'], 0, 10);
            $r['regrinfo']['registered'] = 'yes';
        }
        return $r;
    }

}
