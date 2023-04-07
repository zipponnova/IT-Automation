angular.module('bakshiApp', [])
  .controller('bakshiCtrl', function ($scope, $http) {
    // Your existing controller code...

    $scope.filterFunction = function (row) {
      if ($scope.filters.serialNumber && !row[0].includes($scope.filters.serialNumber)) {
        return false;
      }
      if ($scope.filters.platform && !row[1].includes($scope.filters.platform)) {
        return false;
      }
      if ($scope.filters.nameEmail && !row[2].includes($scope.filters.nameEmail)) {
        return false;
      }
      if ($scope.filters.presence && row[3] !== $scope.filters.presence) {
        return false;
      }
      return true;
    };

    $scope.generateReport = function () {
      // Send POST request to server to generate report
      $http({
        method: 'POST',
        url: '/report',
        data: {
          platform: $scope.filters.platform,
          nameEmail: $scope.filters.nameEmail,
          serialNumber: $scope.filters.serialNumber,
          presence: $scope.filters.presence
        },
        headers: { 'Content-Type': 'application/json' }
      }).then(function successCallback(response) {
        console.log('Report generated successfully');
        // Handle success response
      }, function errorCallback(response) {
        console.error('Error generating report:', response.data);
        // Handle error response
      });
    };
  });
