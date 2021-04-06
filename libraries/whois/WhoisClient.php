<?php
namespace packages\whois;
/**
 * phpWhois basic class
 *
 * This is the basic client class
 */
class WhoisClient
{
    /** @var boolean Is recursion allowed? */
    public $gtldRecurse = false;

    /** @var int Default WHOIS port */
    public $port = 43;

    /** @var int Maximum number of retries on connection failure */
    public $retry = 0;

    /** @var int Time to wait between retries */
    public $sleep = 2;

    /** @var int Read buffer size (0 == char by char) */
    public $buffer = 1024;

    /** @var int Communications timeout */
    public $stimeout = 10;

    /** @var array<string,string> List of servers and handlers (loaded from servers.whois) */
    public $DATA = array();

    /** @var array<string, int> Non UTF-8 servers */
    public $NON_UTF8 = array();

    /** @var string[] List of Whois servers with special parameters */
    public $WHOIS_PARAM = array();

    /** @var string[] TLD's that have special whois servers or that can only be reached via HTTP */
    public $WHOIS_SPECIAL = array();

    /** @var string[] Handled gTLD whois servers */
    public $WHOIS_GTLD_HANDLER = array();

    /** @var mixed Array to contain all query publiciables */
    public $query = array(
        'tld' => '',
        'type' => 'domain',
        'query' => '',
        'status',
        'server',
		'errstr' => []
    );

    /** @var string Current release of the package */
    public $codeVersion = null;

    /** @var string Full code and data version string (e.g. 'Whois2.php v3.01:16') */
    public $version;

    /**
     * Constructor function
     */
    public function __construct()
    {
        // Load DATA array
        $servers = array(
			'DATA' => array(
			    'bz'       => 'gtld',
			    'com'      => 'gtld',
			    'jobs'     => 'gtld',
			    'li'       => 'ch',
			    'net'      => 'gtld',
			    'su'       => 'ru',
			    'tv'       => 'gtld',
			    'za.org'   => 'zanet',
			    'za.net'   => 'zanet',
			    // Punicode
			    'xn--p1ai' => 'ru',
			),

			/* Non UTF-8 servers */

			'NON_UTF8' => array(
			    'br.whois-servers.net'  => 1,
			    'ca.whois-servers.net'  => 1,
			    'cl.whois-servers.net'  => 1,
			    'hu.whois-servers.net'  => 1,
			    'is.whois-servers.net'  => 1,
			    'pt.whois-servers.net'  => 1,
			    'whois.interdomain.net' => 1,
			    'whois.lacnic.net'      => 1,
			    'whois.nicline.com'     => 1,
			    'whois.ripe.net'        => 1,
			),

			/* If whois Server needs any parameters, enter it here */

			'WHOIS_PARAM' => array(
			    'com.whois-servers.net' => 'domain =$',
			    'net.whois-servers.net' => 'domain =$',
			    'de.whois-servers.net'  => '-T dn,ace $',
			    'jp.whois-servers.net'  => 'DOM $/e',
			),

			/* TLD's that have special whois servers or that can only be reached via HTTP */

			'WHOIS_SPECIAL' => array(
			    'ac'                     => 'whois.nic.ac',
			    'academy'                => 'whois.donuts.co',
			    'accountants'            => 'whois.donuts.co',
			    'active'                 => 'whois.afilias-srs.net',
			    'actor'                  => 'whois.unitedtld.com',
			    'ad'                     => '',
			    'ae'                     => 'whois.aeda.net.ae',
			    'aero'                   => 'whois.aero',
			    'af'                     => 'whois.nic.af',
			    'ag'                     => 'whois.nic.ag',
			    'agency'                 => 'whois.donuts.co',
			    'ai'                     => 'whois.ai',
			    'airforce'               => 'whois.unitedtld.com',
			    'al'                     => '',
			    'am'                     => 'whois.amnic.net',
			    'archi'                  => 'whois.ksregistry.net',
			    'army'                   => 'whois.rightside.co',
			    'arpa'                   => 'whois.iana.org',
			    'as'                     => 'whois.nic.as',
			    'asia'                   => 'whois.nic.asia',
			    'associates'             => 'whois.donuts.co',
			    'at'                     => 'whois.nic.at',
			    'attorney'               => 'whois.rightside.co',
			    'au'                     => 'whois.audns.net.au',
			    'auction'                => 'whois.donuts.co',
			    'audio'                  => 'whois.uniregistry.net',
			    'autos'                  => 'whois.afilias-srs.net',
			    'aw'                     => 'whois.nic.aw',
			    'ax'                     => 'whois.ax',
			    'az'                     => '',
			    'ba'                     => '',
			    'bar'                    => 'whois.nic.bar',
			    'bargains'               => 'whois.donuts.co',
			    'bayern'                 => 'whois-dub.mm-registry.com',
			    'bb'                     => 'http://domains.org.bb/regsearch/getdetails.cfm?DND={domain}.bb',
			    'be'                     => 'whois.dns.be',
			    'beer'                   => 'whois-dub.mm-registry.com',
			    'berlin'                 => 'whois.nic.berlin',
			    'best'                   => 'whois.nic.best',
			    'bg'                     => 'whois.register.bg',
			    'bh'                     => 'whois.nic.bh',
			    'bi'                     => 'whois1.nic.bi',
			    'bid'                    => 'whois.nic.bid',
			    'bike'                   => 'whois.donuts.co',
			    'bio'                    => 'whois.ksregistry.net',
			    'biz'                    => 'whois.biz',
			    'bj'                     => 'whois.nic.bj',
			    'black'                  => 'whois.afilias.net',
			    'blackfriday'            => 'whois.uniregistry.net',
			    'blue'                   => 'whois.afilias.net',
			    'bmw'                    => 'whois.ksregistry.net',
			    'bn'                     => 'whois.bn',
			    'bo'                     => 'whois.nic.bo',
			    'boutique'               => 'whois.donuts.co',
			    'br'                     => 'whois.registro.br',
			    'brussels'               => 'whois.nic.brussels',
			    'build'                  => 'whois.nic.build',
			    'builders'               => 'whois.donuts.co',
			    'buzz'                   => 'whois.nic.buzz',
			    'bw'                     => 'whois.nic.net.bw',
			    'by'                     => 'whois.cctld.by',
			    //'bz'                     => 'whois2.afilias-grs.net',
			    'bzh'                    => 'whois-bzh.nic.fr',
			    'ca'                     => 'whois.cira.ca',
			    'cab'                    => 'whois.donuts.co',
			    'camera'                 => 'whois.donuts.co',
			    'camp'                   => 'whois.donuts.co',
			    'cancerresearch'         => 'whois.nic.cancerresearch',
			    'capetown'               => 'capetown-whois.registry.net.za',
			    'capital'                => 'whois.donuts.co',
			    'cards'                  => 'whois.donuts.co',
			    'care'                   => 'whois.donuts.co',
			    'career'                 => 'whois.nic.career',
			    'careers'                => 'whois.donuts.co',
			    'cash'                   => 'whois.donuts.co',
			    'cat'                    => 'whois.cat',
			    'catering'               => 'whois.donuts.co',
			    'cc'                     => 'ccwhois.verisign-grs.com',
			    'center'                 => 'whois.donuts.co',
			    'ceo'                    => 'whois.nic.ceo',
			    'cf'                     => 'whois.dot.cf',
			    'ch'                     => 'whois.nic.ch',
			    'cheap'                  => 'whois.donuts.co',
			    'christmas'              => 'whois.uniregistry.net',
			    'church'                 => 'whois.donuts.co',
			    'ci'                     => 'whois.nic.ci',
			    'city'                   => 'whois.donuts.co',
			    'cl'                     => 'whois.nic.cl',
			    'claims'                 => 'whois.donuts.co',
			    'cleaning'               => 'whois.donuts.co',
			    'clinic'                 => 'whois.donuts.co',
			    'clothing'               => 'whois.donuts.co',
			    'club'                   => 'whois.nic.club',
			    'cn'                     => 'whois.cnnic.cn',
			    'co'                     => 'whois.nic.co',
			    'codes'                  => 'whois.donuts.co',
			    'coffee'                 => 'whois.donuts.co',
			    'college'                => 'whois.centralnic.com',
			    'cologne'                => 'whois-fe1.pdt.cologne.tango.knipp.de',
			    //'com'                    => 'whois.verisign-grs.com',
			    'community'              => 'whois.donuts.co',
			    'company'                => 'whois.donuts.co',
			    'computer'               => 'whois.donuts.co',
			    'condos'                 => 'whois.donuts.co',
			    'construction'           => 'whois.donuts.co',
			    'consulting'             => 'whois.unitedtld.com',
			    'contractors'            => 'whois.donuts.co',
			    'cooking'                => 'whois-dub.mm-registry.com',
			    'cool'                   => 'whois.donuts.co',
			    'coop'                   => 'whois.nic.coop',
			    'country'                => 'whois-dub.mm-registry.com',
			    'credit'                 => 'whois.donuts.co',
			    'creditcard'             => 'whois.donuts.co',
			    'cruises'                => 'whois.donuts.co',
			    'cuisinella'             => 'whois.nic.cuisinella',
			    'cx'                     => 'whois.nic.cx',
			    'cy'                     => '',
			    'cz'                     => 'whois.nic.cz',
			    'dance'                  => 'whois.unitedtld.com',
			    'dating'                 => 'whois.donuts.co',
			    'de'                     => 'whois.denic.de',
			    'deals'                  => 'whois.donuts.co',
			    'degree'                 => 'whois.rightside.co',
			    'democrat'               => 'whois.unitedtld.com',
			    'dental'                 => 'whois.donuts.co',
			    'dentist'                => 'whois.rightside.co',
			    'desi'                   => 'whois.ksregistry.net',
			    'diamonds'               => 'whois.donuts.co',
			    'digital'                => 'whois.donuts.co',
			    'direct'                 => 'whois.donuts.co',
			    'directory'              => 'whois.donuts.co',
			    'discount'               => 'whois.donuts.co',
			    'dk'                     => 'whois.dk-hostmaster.dk',
			    'dm'                     => 'whois.nic.dm',
			    'domains'                => 'whois.donuts.co',
			    'durban'                 => 'durban-whois.registry.net.za',
			    'dz'                     => 'whois.nic.dz',
			    'ec'                     => 'whois.nic.ec',
			    'edu'                    => 'whois.educause.edu',
			    'education'              => 'whois.donuts.co',
			    'ee'                     => 'whois.tld.ee',
			    'email'                  => 'whois.donuts.co',
			    'engineer'               => 'whois.rightside.co',
			    'engineering'            => 'whois.donuts.co',
			    'enterprises'            => 'whois.donuts.co',
			    'equipment'              => 'whois.donuts.co',
			    'es'                     => 'whois.nic.es',
			    'estate'                 => 'whois.donuts.co',
			    'eu'                     => 'whois.eu',
			    'eus'                    => 'whois.eus.coreregistry.net',
			    'events'                 => 'whois.donuts.co',
			    'exchange'               => 'whois.donuts.co',
			    'expert'                 => 'whois.donuts.co',
			    'exposed'                => 'whois.donuts.co',
			    'fail'                   => 'whois.donuts.co',
			    'farm'                   => 'whois.donuts.co',
			    'feedback'               => 'whois.centralnic.com',
			    'fi'                     => 'whois.fi',
			    'finance'                => 'whois.donuts.co',
			    'financial'              => 'whois.donuts.co',
			    'fish'                   => 'whois.donuts.co',
			    'fishing'                => 'whois-dub.mm-registry.com',
			    'fitness'                => 'whois.donuts.co',
			    'fj'                     => 'whois.usp.ac.fj',
			    'flights'                => 'whois.donuts.co',
			    'florist'                => 'whois.donuts.co',
			    'fm'                     => 'http://www.dot.fm/query_whois.cfm?domain={domain}&tld=fm',
			    'fo'                     => 'whois.nic.fo',
			    'foo'                    => 'domain-registry-whois.l.google.com',
			    'foundation'             => 'whois.donuts.co',
			    'fr'                     => 'whois.nic.fr',
			    'frogans'                => 'whois-frogans.nic.fr',
			    'fund'                   => 'whois.donuts.co',
			    'furniture'              => 'whois.donuts.co',
			    'futbol'                 => 'whois.unitedtld.com',
			    'gal'                    => 'whois.gal.coreregistry.net',
			    'gallery'                => 'whois.donuts.co',
			    'gd'                     => 'whois.nic.gd',
			    'gent'                   => 'whois.nic.gent',
			    'gg'                     => 'whois.gg',
			    'gi'                     => 'whois2.afilias-grs.net',
			    'gift'                   => 'whois.uniregistry.net',
			    'gives'                  => 'whois.rightside.co',
			    'gl'                     => 'whois.nic.gl',
			    'glass'                  => 'whois.donuts.co',
			    'global'                 => 'whois.afilias-srs.net',
			    'globo'                  => 'whois.gtlds.nic.br',
			    'gop'                    => 'whois-cl01.mm-registry.com',
			    'gov'                    => 'whois.dotgov.gov',
			    'gr'                     => '',
			    'graphics'               => 'whois.donuts.co',
			    'gratis'                 => 'whois.donuts.co',
			    'green'                  => 'whois.afilias.net',
			    'gripe'                  => 'whois.donuts.co',
			    'gs'                     => 'whois.nic.gs',
			    'gt'                     => 'http://www.gt/Inscripcion/whois.php?domain={domain}.gt',
			    'guide'                  => 'whois.donuts.co',
			    'guitars'                => 'whois.uniregistry.net',
			    'guru'                   => 'whois.donuts.co',
			    'gy'                     => 'whois.registry.gy',
			    'hamburg'                => 'whois.nic.hamburg',
			    'haus'                   => 'whois.unitedtld.com',
			    'hiphop'                 => 'whois.uniregistry.net',
			    'hiv'                    => 'whois.afilias-srs.net',
			    'hk'                     => 'whois.hkirc.hk',
			    'hn'                     => 'whois.nic.hn',
			    'holdings'               => 'whois.donuts.co',
			    'holiday'                => 'whois.donuts.co',
			    'homes'                  => 'whois.afilias-srs.net',
			    'horse'                  => 'whois-dub.mm-registry.com',
			    'host'                   => 'whois.centralnic.com',
			    'house'                  => 'whois.donuts.co',
			    'hr'                     => 'whois.dns.hr',
			    'ht'                     => 'whois.nic.ht',
			    'hu'                     => 'whois.nic.hu',
			    'id'                     => 'whois.pandi.or.id',
			    'ie'                     => 'whois.domainregistry.ie',
			    'il'                     => 'whois.isoc.org.il',
			    'im'                     => 'whois.nic.im',
			    'immobilien'             => 'whois.unitedtld.com',
			    'in'                     => 'whois.inregistry.net',
			    'industries'             => 'whois.donuts.co',
			    'info'                   => 'whois.afilias.net',
			    'ink'                    => 'whois.centralnic.com',
			    'institute'              => 'whois.donuts.co',
			    'insure'                 => 'whois.donuts.co',
			    'int'                    => 'whois.iana.org',
			    'international'          => 'whois.donuts.co',
			    'investments'            => 'whois.donuts.co',
			    'io'                     => 'whois.nic.io',
			    'iq'                     => 'whois.cmc.iq',
			    'ir'                     => 'whois.nic.ir',
			    'is'                     => 'whois.isnic.is',
			    'it'                     => 'whois.nic.it',
			    'je'                     => 'whois.je',
			    'jetzt'                  => 'whois.nic.jetzt',
			    //'jobs'                   => 'jobswhois.verisign-grs.com',
			    'joburg'                 => 'joburg-whois.registry.net.za',
			    'jp'                     => 'whois.jprs.jp',
			    'juegos'                 => 'whois.uniregistry.net',
			    'kaufen'                 => 'whois.unitedtld.com',
			    'ke'                     => 'whois.kenic.or.ke',
			    'kg'                     => 'whois.domain.kg',
			    'ki'                     => 'whois.nic.ki',
			    'kim'                    => 'whois.afilias.net',
			    'kitchen'                => 'whois.donuts.co',
			    'kiwi'                   => 'whois.dot-kiwi.com',
			    'koeln'                  => 'whois-fe1.pdt.koeln.tango.knipp.de',
			    'kr'                     => 'whois.kr',
			    'krd'                    => 'whois.aridnrs.net.au',
			    'kred'                   => 'whois.nic.kred',
			    'kz'                     => 'whois.nic.kz',
			    'la'                     => 'whois.nic.la',
			    'lacaixa'                => 'whois.nic.lacaixa',
			    'land'                   => 'whois.donuts.co',
			    'lawyer'                 => 'whois.rightside.co',
			    'lease'                  => 'whois.donuts.co',
			    'lgbt'                   => 'whois.afilias.net',
			    //'li'                     => 'whois.nic.li',
			    'life'                   => 'whois.donuts.co',
			    'lighting'               => 'whois.donuts.co',
			    'limited'                => 'whois.donuts.co',
			    'limo'                   => 'whois.donuts.co',
			    'link'                   => 'whois.uniregistry.net',
			    'loans'                  => 'whois.donuts.co',
			    'london'                 => 'whois-lon.mm-registry.com',
			    'lotto'                  => 'whois.afilias.net',
			    'lt'                     => 'whois.domreg.lt',
			    'lu'                     => 'whois.dns.lu',
			    'luxe'                   => 'whois-dub.mm-registry.com',
			    'luxury'                 => 'whois.nic.luxury',
			    'lv'                     => 'whois.nic.lv',
			    'ly'                     => 'whois.nic.ly',
			    'ma'                     => 'whois.iam.net.ma',
			    'maison'                 => 'whois.donuts.co',
			    'management'             => 'whois.donuts.co',
			    'mango'                  => 'whois.mango.coreregistry.net',
			    'market'                 => 'whois.rightside.co',
			    'marketing'              => 'whois.donuts.co',
			    'md'                     => 'whois.nic.md',
			    'me'                     => 'whois.nic.me',
			    'media'                  => 'whois.donuts.co',
			    'meet'                   => 'whois.afilias.net',
			    'melbourne'              => 'whois.aridnrs.net.au',
			    'menu'                   => 'whois.nic.menu',
			    'mg'                     => 'whois.nic.mg',
			    'miami'                  => 'whois-dub.mm-registry.com',
			    'mini'                   => 'whois.ksregistry.net',
			    'mk'                     => 'whois.marnet.mk',
			    'ml'                     => 'whois.dot.ml',
			    'mn'                     => 'whois.nic.mn',
			    'mo'                     => 'whois.monic.mo',
			    'mobi'                   => 'whois.dotmobiregistry.net',
			    'moda'                   => 'whois.unitedtld.com',
			    'monash'                 => 'whois.nic.monash',
			    'mortgage'               => 'whois.rightside.co',
			    'moscow'                 => 'whois.nic.moscow',
			    'motorcycles'            => 'whois.afilias-srs.net',
			    'mp'                     => 'whois.nic.mp',
			    'ms'                     => 'whois.nic.ms',
			    'mt'                     => 'http://www.um.edu.mt/cgi-bin/nic/whois?domain={domain}.mt',
			    'mu'                     => 'whois.nic.mu',
			    'museum'                 => 'whois.museum',
			    'mx'                     => 'whois.mx',
			    'my'                     => 'whois.mynic.my',
			    'na'                     => 'whois.na-nic.com.na',
			    'nagoya'                 => 'whois.gmoregistry.net',
			    'name'                   => 'whois.nic.name',
			    'navy'                   => 'whois.rightside.co',
			    'nc'                     => 'whois.nc',
			    //'net'                    => 'whois.verisign-grs.com',
			    'nf'                     => 'whois.nic.nf',
			    'ng'                     => 'whois.nic.net.ng',
			    'ngo'                    => 'whois.publicinterestregistry.net',
			    'ninja'                  => 'whois.unitedtld.com',
			    'nl'                     => 'whois.domain-registry.nl',
			    'no'                     => 'whois.norid.no',
			    'nra'                    => 'whois.afilias-srs.net',
			    'nrw'                    => 'whois-fe1.pdt.nrw.tango.knipp.de',
			    'nu'                     => 'whois.iis.nu',
			    'nyc'                    => 'whois.nic.nyc',
			    'nz'                     => 'whois.srs.net.nz',
			    'okinawa'                => 'whois.gmoregistry.ne',
			    'om'                     => 'whois.registry.om',
			    'onl'                    => 'whois.afilias-srs.net',
			    'org'                    => 'whois.pir.org',
			    'organic'                => 'whois.afilias.net',
			    'ovh'                    => 'whois-ovh.nic.fr',
			    'paris'                  => 'whois-paris.nic.fr',
			    'partners'               => 'whois.donuts.co',
			    'parts'                  => 'whois.donuts.co',
			    'pe'                     => 'kero.yachay.pe',
			    'pf'                     => 'whois.registry.pf',
			    'photo'                  => 'whois.uniregistry.net',
			    'photography'            => 'whois.donuts.co',
			    'photos'                 => 'whois.donuts.co',
			    'physio'                 => 'whois.nic.physio',
			    'pics'                   => 'whois.uniregistry.net',
			    'pictures'               => 'whois.donuts.co',
			    'pink'                   => 'whois.afilias.net',
			    'pl'                     => 'whois.dns.pl',
			    'place'                  => 'whois.donuts.co',
			    'plumbing'               => 'whois.donuts.co',
			    'pm'                     => 'whois.nic.pm',
			    'post'                   => 'whois.dotpostregistry.net',
			    'pr'                     => 'whois.nic.pr',
			    'press'                  => 'whois.centralnic.com',
			    'pro'                    => 'whois.dotproregistry.net',
			    'productions'            => 'whois.donuts.co',
			    'properties'             => 'whois.donuts.co',
			    'pt'                     => 'whois.dns.pt',
			    'pub'                    => 'whois.unitedtld.com',
			    'pw'                     => 'whois.nic.pw',
			    'qa'                     => 'whois.registry.qa',
			    'qpon'                   => 'whois.nic.qpon',
			    'quebec'                 => 'whois.quebec.rs.corenic.net',
			    're'                     => 'whois.nic.re',
			    'recipes'                => 'whois.donuts.co',
			    'red'                    => 'whois.afilias.net',
			    'rehab'                  => 'whois.rightside.co',
			    'reise'                  => 'whois.nic.reise',
			    'reisen'                 => 'whois.donuts.co',
			    'rentals'                => 'whois.donuts.co',
			    'repair'                 => 'whois.donuts.co',
			    'report'                 => 'whois.donuts.co',
			    'republican'             => 'whois.rightside.co',
			    'rest'                   => 'whois.centralnic.com',
			    'reviews'                => 'whois.unitedtld.com',
			    'rich'                   => 'whois.afilias-srs.net',
			    'rio'                    => 'whois.gtlds.nic.br',
			    'ro'                     => 'whois.rotld.ro',
			    'rocks'                  => 'whois.unitedtld.com',
			    'rodeo'                  => 'whois-dub.mm-registry.com',
			    'rs'                     => 'whois.rnids.rs',
			    'ru'                     => 'whois.tcinet.ru',
			    'ruhr'                   => 'whois.nic.ruhr',
			    'sa'                     => 'whois.nic.net.sa',
			    'saarland'               => 'whois.ksregistry.net',
			    'sb'                     => 'whois.nic.net.sb',
			    'sc'                     => 'whois2.afilias-grs.net',
			    'scb'                    => 'whois.nic.scb',
			    'schmidt'                => 'whois.nic.schmidt',
			    'schule'                 => 'whois.donuts.co',
			    'scot'                   => 'whois.scot.coreregistry.net',
			    'se'                     => 'whois.iis.se',
			    'services'               => 'whois.donuts.co',
			    'sexy'                   => 'whois.uniregistry.net',
			    'sg'                     => 'whois.sgnic.sg',
			    'sh'                     => 'whois.nic.sh',
			    'shiksha'                => 'whois.afilias.net',
			    'shoes'                  => 'whois.donuts.co',
			    'si'                     => 'whois.arnes.si',
			    'singles'                => 'whois.donuts.co',
			    'sk'                     => 'whois.sk-nic.sk',
			    'sm'                     => 'whois.nic.sm',
			    'sn'                     => 'whois.nic.sn',
			    'so'                     => 'whois.nic.so',
			    'social'                 => 'whois.unitedtld.com',
			    'software'               => 'whois.rightside.co',
			    'sohu'                   => 'whois.gtld.knet.cn',
			    'solar'                  => 'whois.donuts.co',
			    'solutions'              => 'whois.donuts.co',
			    'soy'                    => 'domain-registry-whois.l.google.com',
			    'space'                  => 'whois.nic.space',
			    'spiegel'                => 'whois.ksregistry.net',
			    'st'                     => 'whois.nic.st',
			    'su'                     => 'whois.tcinet.ru',
			    'supplies'               => 'whois.donuts.co',
			    'supply'                 => 'whois.donuts.co',
			    'support'                => 'whois.donuts.co',
			    'surf'                   => 'whois-dub.mm-registry.com',
			    'surgery'                => 'whois.donuts.co',
			    'sx'                     => 'whois.sx',
			    'sy'                     => 'whois.tld.sy',
			    'systems'                => 'whois.donuts.co',
			    'tattoo'                 => 'whois.uniregistry.net',
			    'tax'                    => 'whois.donuts.co',
			    'tc'                     => 'whois.meridiantld.net',
			    'technology'             => 'whois.donuts.co',
			    'tel'                    => 'whois.nic.tel',
			    'tf'                     => 'whois.nic.tf',
			    'th'                     => 'whois.thnic.co.th',
			    'tienda'                 => 'whois.donuts.co',
			    'tips'                   => 'whois.donuts.co',
			    'tirol'                  => 'whois.nic.tirol',
			    'tk'                     => 'whois.dot.tk',
			    'tl'                     => 'whois.nic.tl',
			    'tm'                     => 'whois.nic.tm',
			    'tn'                     => 'whois.ati.tn',
			    'to'                     => 'whois.tonic.to',
			    'today'                  => 'whois.donuts.co',
			    'tokyo'                  => 'whois.nic.tokyo',
			    'tools'                  => 'whois.donuts.co',
			    'town'                   => 'whois.donuts.co',
			    'toys'                   => 'whois.donuts.co',
			    'tr'                     => 'whois.nic.tr',
			    'trade'                  => 'whois.nic.trade',
			    'training'               => 'whois.donuts.co',
			    'travel'                 => 'whois.nic.travel',
			    //'tv'                     => 'tvwhois.verisign-grs.com',
			    'tw'                     => 'whois.twnic.net.tw',
			    'tz'                     => 'whois.tznic.or.tz',
			    'ua'                     => 'whois.ua',
			    'ug'                     => 'whois.co.ug',
			    'uk'                     => 'whois.nic.uk',
			    'university'             => 'whois.donuts.co',
			    'uno'                    => 'whois.nic.uno',
			    'us'                     => 'whois.nic.us',
			    'uy'                     => 'whois.nic.org.uy',
			    'uz'                     => 'whois.cctld.uz',
			    'vacations'              => 'whois.donuts.co',
			    'vc'                     => 'whois2.afilias-grs.net',
			    've'                     => 'whois.nic.ve',
			    'vegas'                  => 'whois.afilias-srs.net',
			    'ventures'               => 'whois.donuts.co',
			    'versicherung'           => 'whois.nic.versicherung',
			    'vet'                    => 'whois.rightside.co',
			    'vg'                     => 'ccwhois.ksregistry.net',
			    'viajes'                 => 'whois.donuts.co',
			    'villas'                 => 'whois.donuts.co',
			    'vision'                 => 'whois.donuts.co',
			    'vlaanderen'             => 'whois.nic.vlaanderen',
			    'vodka'                  => 'whois-dub.mm-registry.com',
			    'vote'                   => 'whois.afilias.net',
			    'voting'                 => 'whois.voting.tld-box.at',
			    'voto'                   => 'whois.afilias.net',
			    'voyage'                 => 'whois.donuts.co',
			    'vu'                     => 'vunic.vu',
			    'wang'                   => 'whois.gtld.knet.cn',
			    'watch'                  => 'whois.donuts.co',
			    'webcam'                 => 'whois.nic.webcam',
			    'website'                => 'whois.nic.website',
			    'wed'                    => 'whois.nic.wed',
			    'wf'                     => 'whois.nic.wf',
			    'wien'                   => 'whois.nic.wien',
			    'wiki'                   => 'whois.nic.wiki',
			    'works'                  => 'whois.donuts.co',
			    'ws'                     => 'whois.website.ws',
			    'wtc'                    => 'whois.nic.wtc',
			    'wtf'                    => 'whois.donuts.co',
			    'xxx'                    => 'whois.nic.xxx',
			    'xyz'                    => 'whois.nic.xyz',
			    'yachts'                 => 'whois.afilias-srs.net',
			    'yt'                     => 'whois.nic.yt',
			    'zip'                    => 'domain-registry-whois.l.google.com',
			    'zm'                     => 'whois.nic.zm',
			    'zone'                   => 'whois.donuts.co',

			    // Second level
			    'net.au'                 => 'whois.aunic.net',
			    'ae.com'                 => 'whois.centralnic.net',
			    'br.com'                 => 'whois.centralnic.net',
			    'cn.com'                 => 'whois.centralnic.net',
			    'de.com'                 => 'whois.centralnic.net',
			    'eu.com'                 => 'whois.centralnic.net',
			    'gb.com'                 => 'whois.centralnic.net',
			    'hu.com'                 => 'whois.centralnic.net',
			    'jpn.com'                => 'whois.centralnic.net',
			    'kr.com'                 => 'whois.centralnic.net',
			    'no.com'                 => 'whois.centralnic.net',
			    'qc.com'                 => 'whois.centralnic.net',
			    'ru.com'                 => 'whois.centralnic.net',
			    'sa.com'                 => 'whois.centralnic.net',
			    'se.com'                 => 'whois.centralnic.net',
			    'uk.com'                 => 'whois.centralnic.net',
			    'us.com'                 => 'whois.centralnic.net',
			    'uy.com'                 => 'whois.centralnic.net',
			    'za.com'                 => 'whois.centralnic.net',
			    'com.my'                 => 'whois.mynic.net.my',
			    'gb.net'                 => 'whois.centralnic.net',
			    'se.net'                 => 'whois.centralnic.net',
			    'uk.net'                 => 'whois.centralnic.net',
			    'za.net'                 => 'http://www.za.net/cgi-bin/whois.cgi?domain={domain}.za.net',
			    'za.org'                 => 'http://www.za.net/cgi-bin/whois.cgi?domain={domain}.za.org',
			    'com.ru'                 => 'whois.nic.ru',
			    'msk.ru'                 => 'whois.nic.ru',
			    'net.ru'                 => 'whois.nic.ru',
			    'org.ru'                 => 'whois.nic.ru',
			    'pp.ru'                  => 'whois.nic.ru',
			    'sochi.su'               => 'whois.nic.ru',
			    'co.za'                  => 'http://co.za/cgi-bin/whois.sh?Domain={domain}.co.za',
			    'org.za'                 => 'http://www.org.za/cgi-bin/rwhois?domain={domain}.org.za&format=full',

			    // National tlds
			    'xn--3bst00m'            => 'whois.gtld.knet.cn',
			    'xn--3ds443g'            => 'whois.afilias-srs.net',
			    'xn--3e0b707e'           => 'whois.kr',
			    'xn--4gbrim'             => 'whois.afilias-srs.net',
			    'xn--55qw42g'            => 'whois.conac.cn',
			    'xn--55qx5d'             => 'whois.ngtld.cn',
			    'xn--6frz82g'            => 'whois.afilias.net',
			    'xn--6qq986b3xl'         => 'whois.gtld.knet.cn',
			    'xn--80adxhks'           => 'whois.nic.xn--80adxhks',
			    'xn--80ao21a'            => 'whois.nic.kz',
			    'xn--80asehdb'           => 'whois.online.rs.corenic.net',
			    'xn--80aswg'             => 'whois.site.rs.corenic.net',
			    'xn--c1avg'              => 'whois.publicinterestregistry.net',
			    'xn--cg4bki'             => 'whois.kr',
			    'xn--clchc0ea0b2g2a9gcd' => 'whois.sgnic.sg',
			    'xn--czru2d'             => 'whois.gtld.knet.cn',
			    'xn--d1acj3b'            => 'whois.nic.xn--d1acj3b',
			    'xn--fiq228c5hs'         => 'whois.afilias-srs.net',
			    'xn--fiq64b'             => 'whois.gtld.knet.cn',
			    'xn--fiqs8s'             => 'cwhois.cnnic.cn',
			    'xn--fiqz9s'             => 'cwhois.cnnic.cn',
			    'xn--i1b6b1a6a2e'        => 'whois.publicinterestregistry.net',
			    'xn--io0a7i'             => 'whois.ngtld.cn',
			    'xn--j1amh'              => 'whois.dotukr.com',
			    'xn--j6w193g'            => 'whois.hkirc.hk',
			    'xn--kprw13d'            => 'whois.twnic.net.tw',
			    'xn--kpry57d'            => 'whois.twnic.net.tw',
			    'xn--lgbbat1ad8j'        => 'whois.nic.dz',
			    'xn--mgb9awbf'           => 'whois.registry.om',
			    'xn--mgba3a4f16a'        => 'whois.nic.ir',
			    'xn--mgbaam7a8h'         => 'whois.aeda.net.ae',
			    'xn--mgbab2bd'           => 'whois.bazaar.coreregistry.net',
			    'xn--mgberp4a5d4ar'      => 'whois.nic.net.sa',
			    'xn--mgbx4cd0ab'         => 'whois.mynic.my',
			    'xn--ngbc5azd'           => 'whois.nic.xn--ngbc5azd',
			    'xn--nqv7f'              => 'whois.publicinterestregistry.net',
			    'xn--nqv7fs00ema'        => 'whois.publicinterestregistry.net',
			    'xn--o3cw4h'             => 'whois.thnic.co.th',
			    'xn--ogbpf8fl'           => 'whois.tld.sy',
			    'xn--p1ai'               => 'whois.tcinet.ru',
			    'xn--q9jyb4c'            => 'domain-registry-whois.l.google.com',
			    'xn--rhqv96g'            => 'whois.nic.xn--rhqv96g',
			    'xn--unup4y'             => 'whois.donuts.co',
			    'xn--wgbl6a'             => 'whois.registry.qa',
			    'xn--yfro4i67o'          => 'whois.sgnic.sg',
			    'xn--ygbi2ammx'          => 'whois.pnina.ps',
			    'xn--zfr164b'            => 'whois.conac.cn',
			),

			/* handled gTLD whois servers */

			'WHOIS_GTLD_HANDLER' => array(
			    'whois.bulkregister.com' => 'enom',
			    'whois.dotregistrar.com' => 'dotster',
			    'whois.namesdirect.com'  => 'dotster',
			    'whois.psi-usa.info'     => 'psiusa',
			    'whois.www.tv'           => 'tvcorp',
			    'whois.tucows.com'       => 'opensrs',
			    'whois.35.com'           => 'onlinenic',
			    'whois.nominalia.com'    => 'genericb',
			    'whois.encirca.com'      => 'genericb',
			    'whois.corenic.net'      => 'genericb'
			),
		);

        $this->DATA               = $servers['DATA'];
        $this->NON_UTF8           = $servers['NON_UTF8'];
        $this->WHOIS_PARAM        = $servers['WHOIS_PARAM'];
        $this->WHOIS_SPECIAL      = $servers['WHOIS_SPECIAL'];
        $this->WHOIS_GTLD_HANDLER = $servers['WHOIS_GTLD_HANDLER'];

        $this->codeVersion = "5.0.0-dev";
        // Set version
        $this->version = sprintf("phpWhois v%s", $this->codeVersion);
    }

    /**
     * Perform lookup
     *
     * @return array Raw response as array separated by "\n"
     */
    public function getRawData($query)
    {

        $this->query['query'] = $query;

        // clear error description
        if (isset($this->query['errstr'])) {
            unset($this->query['errstr']);
        }
        if (!isset($this->query['server'])) {
            $this->query['status'] = 'error';
            $this->query['errstr'] = ['No server specified'];
            return (array());
        }

        // Check if protocol is http
        if (substr($this->query['server'], 0, 7) == 'http://' ||
            substr($this->query['server'], 0, 8) == 'https://'
        ) {
            $output = $this->httpQuery();

            if (!$output) {
                $this->query['status'] = 'error';
                $this->query['errstr'] = ['Connect failed to: ' . $this->query['server']];
                return (array());
            }

            $this->query['args'] = substr(strchr($this->query['server'], '?'), 1);
            $this->query['server'] = strtok($this->query['server'], '?');

            if (substr($this->query['server'], 0, 7) == 'http://') {
                $this->query['server_port'] = 80;
            } else {
                $this->query['server_port'] = 443;
            }
        } else {
            // Get args
            if (strpos($this->query['server'], '?')) {
                $parts = explode('?', $this->query['server']);
                $this->query['server'] = trim($parts[0]);
                $query_args = trim($parts[1]);

                // replace substitution parameters
                $query_args = str_replace('{query}', $query, $query_args);
                $query_args = str_replace('{version}', 'phpWhois' . $this->codeVersion, $query_args);

                $iptools = new IpTools;
                if (strpos($query_args, '{ip}') !== false) {
                    $query_args = str_replace('{ip}', $iptools->getClientIp(), $query_args);
                }

                if (strpos($query_args, '{hname}') !== false) {
                    $query_args = str_replace('{hname}', gethostbyaddr($iptools->getClientIp()), $query_args);
                }
            } else {
                if (empty($this->query['args'])) {
                    $query_args = $query;
                } else {
                    $query_args = $this->query['args'];
                }
            }

            $this->query['args'] = $query_args;

            if (substr($this->query['server'], 0, 9) == 'rwhois://') {
                $this->query['server'] = substr($this->query['server'], 9);
            }

            if (substr($this->query['server'], 0, 8) == 'whois://') {
                $this->query['server'] = substr($this->query['server'], 8);
            }

            // Get port
            if (strpos($this->query['server'], ':')) {
                $parts = explode(':', $this->query['server']);
                $this->query['server'] = trim($parts[0]);
                $this->query['server_port'] = trim($parts[1]);
            } else {
                $this->query['server_port'] = $this->port;
            }

            // Connect to whois server, or return if failed
            $ptr = $this->connect();

            if ($ptr === false) {
                $this->query['status'] = 'error';
                $this->query['errstr'] = ['Connect failed to: ' . $this->query['server']];
                return array();
            }

            stream_set_timeout($ptr, $this->stimeout);
            stream_set_blocking($ptr, 0);

            // Send query
            fputs($ptr, trim($query_args) . "\r\n");

            // Prepare to receive result
            $raw = '';
            $start = time();
            $null = null;
            $r = array($ptr);

            while (!feof($ptr)) {
                if (!empty($r)) {
                    if (stream_select($r, $null, $null, $this->stimeout)) {
                        $raw .= fgets($ptr, $this->buffer);
                    }
                }

                if (time() - $start > $this->stimeout) {
                    $this->query['status'] = 'error';
                    $this->query['errstr'] = ['Timeout reading from ' . $this->query['server']];
                    return array();
                }
            }

            if (array_key_exists($this->query['server'], $this->NON_UTF8)) {
                $raw = utf8_encode($raw);
            }

            $output = explode("\n", $raw);

            // Drop empty last line (if it's empty! - saleck)
            if (empty($output[count($output) - 1])) {
                unset($output[count($output) - 1]);
            }
        }

        return $output;
    }

    /**
     * Perform lookup
     *
     * @return array The *rawdata* element contains an
     * array of lines gathered from the whois query. If a top level domain
     * handler class was found for the domain, other elements will have been
     * populated too.
     */

    public function getData($query = '', $deep_whois = true)
    {

        // If domain to query passed in, use it, otherwise use domain from initialisation
        $query = !empty($query) ? $query : $this->query['query'];

        $output = $this->getRawData($query);

        // Create result and set 'rawdata'
        $result = array('rawdata' => $output);
        $result = $this->setWhoisInfo($result);

        // Return now on error
        if (empty($output)) {
            return $result;
        }

        // If we have a handler, post-process it with it
        if (isset($this->query['handler'])) {
            // Keep server list
            $servers = $result['regyinfo']['servers'];
            unset($result['regyinfo']['servers']);

            // Process data
            $result = $this->process($result, $deep_whois);

            // Add new servers to the server list
            if (isset($result['regyinfo']['servers'])) {
                $result['regyinfo']['servers'] = array_merge($servers, $result['regyinfo']['servers']);
            } else {
                $result['regyinfo']['servers'] = $servers;
            }

            // Handler may forget to set rawdata
            if (!isset($result['rawdata'])) {
                $result['rawdata'] = $output;
            }
        }

        // Type defaults to domain
        if (!isset($result['regyinfo']['type'])) {
            $result['regyinfo']['type'] = 'domain';
        }

        // Add error information if any
        if (isset($this->query['errstr'])) {
            $result['errstr'] = $this->query['errstr'];
        }

        // Fix/add nameserver information
        if (method_exists($this, 'fixResult') && $this->query['tld'] != 'ip') {
            $this->fixResult($result, $query);
        }

        return ($result);
    }

    /**
     * Adds whois server query information to result
     *
     * @param array $result Result array
     * @return array Original result array with server query information
     */
    public function setWhoisInfo($result)
    {
        $info = array(
            'server' => $this->query['server'],
        );

        if (!empty($this->query['args'])) {
            $info['args'] = $this->query['args'];
        } else {
            $info['args'] = $this->query['query'];
        }

        if (!empty($this->query['server_port'])) {
            $info['port'] = $this->query['server_port'];
        } else {
            $info['port'] = 43;
        }

        if (isset($result['regyinfo']['whois'])) {
            unset($result['regyinfo']['whois']);
        }

        if (isset($result['regyinfo']['rwhois'])) {
            unset($result['regyinfo']['rwhois']);
        }

        $result['regyinfo']['servers'][] = $info;

        return $result;
    }

    /**
     * Convert html output to plain text
     *
     * @return array|null Rawdata
     */
    public function httpQuery()
    {

        //echo ini_get('allow_url_fopen');
        //if (ini_get('allow_url_fopen'))
        $lines = @file($this->query['server']);

        if (!$lines) {
            return null;
        }

        $output = '';
        $pre = '';

        while (list($key, $val) = each($lines)) {
            $val = trim($val);

            $pos = strpos(strtoupper($val), '<PRE>');
            if ($pos !== false) {
                $pre = "\n";
                $output .= substr($val, 0, $pos) . "\n";
                $val = substr($val, $pos + 5);
            }
            $pos = strpos(strtoupper($val), '</PRE>');
            if ($pos !== false) {
                $pre = '';
                $output .= substr($val, 0, $pos) . "\n";
                $val = substr($val, $pos + 6);
            }
            $output .= $val . $pre;
        }

        $search = array(
            '<BR>', '<P>', '</TITLE>',
            '</H1>', '</H2>', '</H3>',
            '<br>', '<p>', '</title>',
            '</h1>', '</h2>', '</h3>');

        $output = str_replace($search, "\n", $output);
        $output = str_replace('<TD', ' <td', $output);
        $output = str_replace('<td', ' <td', $output);
        $output = str_replace('<tr', "\n<tr", $output);
        $output = str_replace('<TR', "\n<tr", $output);
        $output = str_replace('&nbsp;', ' ', $output);
        $output = strip_tags($output);
        $output = explode("\n", $output);

        $rawdata = array();
        $null = 0;

        while (list($key, $val) = each($output)) {
            $val = trim($val);
            if ($val == '') {
                if (++$null > 2) {
                    continue;
                }
            } else {
                $null = 0;
            }
            $rawdata[] = $val;
        }
        return $rawdata;
    }

    /**
     * Open a socket to the whois server.
     *
     * @param string|null $server Server address to connect. If null, $this->query['server'] will be used
     *
     * @return resource|false Returns a socket connection pointer on success, or -1 on failure
     */
    public function connect($server = null)
    {

        if (empty($server)) {
            $server = $this->query['server'];
        }

        /** @TODO Throw an exception here */
        if (empty($server)) {
            return false;
        }

        $port = $this->query['server_port'];

        $parsed = $this->parseServer($server);
        $server = $parsed['host'];

        if (array_key_exists('port', $parsed)) {
            $port = $parsed['port'];
        }

        // Enter connection attempt loop
        $retry = 0;

        while ($retry <= $this->retry) {
            // Set query status
            $this->query['status'] = 'ready';

            // Connect to whois port
            $ptr = @fsockopen($server, $port, $errno, $errstr, $this->stimeout);

            if ($ptr > 0) {
                $this->query['status'] = 'ok';
                return $ptr;
            }

            // Failed this attempt
            $this->query['status'] = 'error';
            $this->query['error'][] = $errstr;
            $retry++;

            // Sleep before retrying
            sleep($this->sleep);
        }

        // If we get this far, it hasn't worked
        return false;
    }

    /**
     * Post-process result with handler class.
     *
     * @return array On success, returns the result from the handler.
     * On failure, returns passed result unaltered.
     */

    public function process(&$result, $deep_whois = true)
    {

        $handler_name = str_replace('.', '_', $this->query['handler']);

        if (!$this->gtldRecurse && $this->query['file'] == 'whois.gtld.php') {
            return $result;
        }

        // Pass result to handler
        $object = __NAMESPACE__.'\\'.$handler_name . '_handler';

        $handler = new $object('');

        // If handler returned an error, append it to the query errors list
        if (isset($handler->query['errstr'])) {
            $this->query['errstr'][] = $handler->query['errstr'];
        }

        $handler->deepWhois = $deep_whois;

        // Process
        $res = $handler->parse($result, $this->query['query']);

        // Return the result
        return $res;
    }

    /**
     * Does more (deeper) whois
     *
     * @return array Resulting array
     */
    public function deepWhois($query, $result)
    {

        if (!isset($result['regyinfo']['whois'])) {
            return $result;
        }

        $this->query['server'] = $wserver = $result['regyinfo']['whois'];
        unset($result['regyinfo']['whois']);
        $subresult = $this->getRawData($query);

        if (!empty($subresult)) {
            $result = $this->setWhoisInfo($result);
            $result['rawdata'] = $subresult;

            if (isset($this->WHOIS_GTLD_HANDLER[$wserver])) {
                $this->query['handler'] = $this->WHOIS_GTLD_HANDLER[$wserver];
            } else {
                $parts = explode('.', $wserver);
                $hname = strtolower($parts[1]);

                if (($fp = @fopen('whois.gtld.' . $hname . '.php', 'r', 1)) and fclose($fp)) {
                    $this->query['handler'] = $hname;
                }
            }

            if (!empty($this->query['handler'])) {
                $this->query['file'] = sprintf('whois.gtld.%s.php', $this->query['handler']);
                $regrinfo = $this->process($subresult); //$result['rawdata']);
                $result['regrinfo'] = $this->mergeResults($result['regrinfo'], $regrinfo);
                //$result['rawdata'] = $subresult;
            }
        }

        return $result;
    }

    /**
     * Merge results
     *
     * @param array $a1
     * @param array $a2
     *
     * @return array
     */
    public function mergeResults($a1, $a2)
    {

        reset($a2);

        while (list($key, $val) = each($a2)) {
            if (isset($a1[$key])) {
                if (is_array($val)) {
                    if ($key != 'nserver') {
                        $a1[$key] = $this->mergeResults($a1[$key], $val);
                    }
                } else {
                    $val = trim($val);
                    if ($val != '') {
                        $a1[$key] = $val;
                    }
                }
            } else {
                $a1[$key] = $val;
            }
        }

        return $a1;
    }

    /**
     * Remove unnecessary symbols from nameserver received from whois server
     *
     * @param string[] $nserver List of received nameservers
     *
     * @return string[]
     */
    public function fixNameServer($nserver)
    {
        $dns = array();

        foreach ($nserver as $val) {
            $val = str_replace(array('[', ']', '(', ')'), '', trim($val));
            $val = str_replace("\t", ' ', $val);
            $parts = explode(' ', $val);
            $host = '';
            $ip = '';

            foreach ($parts as $p) {
                if (substr($p, -1) == '.') {
                    $p = substr($p, 0, -1);
                }

                if ((ip2long($p) == -1) or (ip2long($p) === false)) {
                    // Hostname ?
                    if ($host == '' && preg_match('/^[\w\-]+(\.[\w\-]+)+$/', $p)) {
                        $host = $p;
                    }
                } else {
                    // IP Address
                    $ip = $p;
                }
            }

            // Valid host name ?
            if ($host == '') {
                continue;
            }

            // Get ip address
            if ($ip == '') {
                $ip = gethostbyname($host);
                if ($ip == $host) {
                    $ip = '(DOES NOT EXIST)';
                }
            }

            if (substr($host, -1, 1) == '.') {
                $host = substr($host, 0, -1);
            }

            $dns[strtolower($host)] = $ip;
        }

        return $dns;
    }

    /**
     * Parse server string into array with host and port keys
     *
     * @param string $server   server in various formattes
     * @return array    Array containing 'host' key with server host and 'port' if defined in original $server string
     */
    public function parseServer($server)
    {
        $server = trim($server);

        $server = preg_replace('/\/$/', '', $server);
        $ipTools = new IpTools;
        if ($ipTools->validIpv6($server)) {
            $result = array('host' => "[$server]");
        } else {
            $parsed = parse_url($server);
            if (array_key_exists('path', $parsed) && !array_key_exists('host', $parsed)) {
                $host = preg_replace('/\//', '', $parsed['path']);

                // if host is ipv6 with port. Example: [1a80:1f45::ebb:12]:8080
                if (preg_match('/^(\[[a-f0-9:]+\]):(\d{1,5})$/i', $host, $matches)) {
                    $result = array('host' => $matches[1], 'port' => $matches[2]);
                } else {
                    $result = array('host' => $host);
                }
            } else {
                $result = $parsed;
            }
        }
        return $result;
    }
}
