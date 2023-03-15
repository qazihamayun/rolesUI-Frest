
<style type="text/css">
    .no-border tr th{
        border:none !important;
    }
    .no-border tr td{
        border: none !important;
    }

    tr p{
        margin: 2px !important;
    }

    table.bold td, table.bold td {
        font-weight: bold;
    }

    ol.bold li, ul.bold li{
        font-weight:bold;
    }

    .td-page-break {page-break-after: always;}
    @media print {
        .td-page-break {page-break-after: always;}
    }

    .table_no_border tr th, .table_no_border tr td{
        border:none !important;
    }
</style>

<div class="report_header borderb show_in_print">

    <div class="header_logo" style="width: 20%; float: left;">
        <img src="{!! asset('assets/img/kpk_logo.png') !!}" alt="" width="80px">
    </div>

    <div class="header_desc" style="width: 60%; float: left">
{{--        <h4 class="text-center">Government of Khyber Pakhtunkhwa <br> {{ \Modules\Settings\Entities\Company::findOrFail(auth()->user()->department_id)->title }}</h4>--}}
        <h4 class="text-center">Government of Khyber Pakhtunkhwa <br>
            Reporting Department
        </h4>

        <h5 class="text-center">{{ $title }}</h5>
{{--        @if(auth()->check())--}}
{{--            <h5 class="text-center">Presiding Officer: {{ auth()->user()->title }}</h5>--}}
{{--        @endif--}}
        <h6 class="text-center">Dated: <?php echo date("d-M-Y") ?></h6>

    </div>


    <div style="width: 20%; float: right; text-align: right;">
            <img src="{!! asset('assets/img/kpitb_logo.png') !!}" alt="" width="80px">
    </div>

    <div style="clear: both;"></div>

</div>
