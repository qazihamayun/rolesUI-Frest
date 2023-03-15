@extends('layouts.app_screen_frest_vms')
@php $app_id = config('vms.app_id') @endphp
@section('title', 'Visitor Detail')

@section('content')

    <!--  Navbar Starts / Breadcrumb Area  -->
    <div class="sub-header-container">
        <header class="header navbar navbar-expand-sm">
            <a href="javascript:void(0);" class="sidebarCollapse" data-placement="bottom">
                <i class="las la-bars"></i>
            </a>
            <ul class="navbar-nav flex-row">
                <li>
                    <div class="page-header">
                        <nav class="breadcrumb-one" aria-label="breadcrumb">
                            <ol class="breadcrumb">
                                <li class="breadcrumb-item"><a href="javascript:void(0);">{{ __('Visitors') }}</a></li>
                            </ol>
                        </nav>
                    </div>
                </li>
            </ul>
        </header>
    </div>
    <!--  Navbar Ends / Breadcrumb Area  -->
    <!-- Main Body Starts -->
    <div class="layout-px-spacing">
        <div class="layout-top-spacing mb-2">
            <div class="col-md-12">
                <div class="row">
                    <div class="container p-0">
                        <div class="row layout-top-spacing date-table-container">

                            <!-- Datatable go to last page -->
                            <div class="col-xl-12 col-lg-12 col-sm-12  layout-spacing">
                                <div class="widget-content widget-content-area br-6">
                                    <div class="row">
                                        <div class="col-sm-10">
                                            <h4 class="table-header">{{ __('  Visitor Details ') }}</h4>
                                        </div>
                                        <div class="col-sm-2 text-right">
                                            @can('visitor-list')
                                                <a href="{{ route('visitors.index') }}" class="btn btn-primary">Back</a>
                                            @endcan
                                        </div>
                                    </div>
                                    <div class="table-responsive mb-4">

                                        <table id="last-page-dt" class="table table-hover" style="width:100%">
                                            <thead>
                                                <tr>
                                                    <th>Name</th>
                                                    <td>
                                                        {{ $visitor->user()->exists() ? $visitor->user->name : '' }}

                                                    </td>
                                                </tr>
                                                <tr>
                                                    <th>Email</th>
                                                    <td>
                                                        {{ $visitor->user()->exists() ? $visitor->user->email : '' }}

                                                    </td>
                                                </tr>
                                                <tr>
                                                    <th>Cnic</th>
                                                    <td>
                                                        {{ $visitor->user()->exists() ? $visitor->user->cnic : '' }}

                                                    </td>
                                                </tr>
                                                <tr>
                                                    <th>Department</th>
                                                    <td>
                                                        {{ $visitor->department()->exists() ? $visitor->department->title : '' }}

                                                    </td>
                                                </tr>
                                            </thead>
                                        </table>
                                    </div>
                                </div>

                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- Main Body Ends -->
@endsection

@push('plugin-scripts')
    {!! Html::script('assets/js/loader.js') !!}
    {!! Html::script('plugins/table/datatable/datatables.js') !!}
@endpush
